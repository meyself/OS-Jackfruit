/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE          (1024 * 1024)
#define CONTAINER_ID_LEN    32
#define CONTROL_PATH        "/tmp/mini_runtime.sock"
#define LOG_DIR             "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN   256
#define LOG_CHUNK_SIZE      4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT  (40UL << 20)
#define DEFAULT_HARD_LIMIT  (64UL << 20)
#define MAX_LOG_FILES       64
#define STOP_TIMEOUT_SEC    5

/* ---------------------------------------------------------------
 * Types and structs
 * --------------------------------------------------------------- */

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
    size_t payload_len;
} control_response_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    pthread_cond_t metadata_changed;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    int pipe_fd;
    char container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *log_buffer;
} producer_args_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int client_fd;
} client_thread_args_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    int fd;
} log_file_entry_t;

/* Self-pipe for delivering signals to the main event loop */
static int g_sig_pipe[2] = {-1, -1};

/* ---------------------------------------------------------------
 * Signal handlers (async-signal-safe)
 * --------------------------------------------------------------- */

static void sigchld_handler(int sig)
{
    char c = 'C';
    (void)sig;
    (void)write(g_sig_pipe[1], &c, 1);
}

static void shutdown_handler(int sig)
{
    char c = 'S';
    (void)sig;
    (void)write(g_sig_pipe[1], &c, 1);
}

/* ---------------------------------------------------------------
 * Argument parsing helpers
 * --------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command>"
            " [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command>"
            " [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc, char *argv[],
                                int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1],
                               &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1],
                               &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

/* ---------------------------------------------------------------
 * Bounded Buffer
 * --------------------------------------------------------------- */

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;
    memset(buffer, 0, sizeof(*buffer));
    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }
    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    if (buffer->count == 0) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/* ---------------------------------------------------------------
 * Logging Consumer Thread
 * --------------------------------------------------------------- */

void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    log_file_entry_t log_files[MAX_LOG_FILES];
    int num_files = 0;
    int i;

    for (i = 0; i < MAX_LOG_FILES; i++) {
        log_files[i].fd = -1;
        log_files[i].container_id[0] = '\0';
    }

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        int fd = -1;

        for (i = 0; i < num_files; i++) {
            if (strcmp(log_files[i].container_id, item.container_id) == 0) {
                fd = log_files[i].fd;
                break;
            }
        }

        if (fd < 0 && num_files < MAX_LOG_FILES) {
            char log_path[PATH_MAX];
            container_record_t *c;

            log_path[0] = '\0';
            pthread_mutex_lock(&ctx->metadata_lock);
            c = ctx->containers;
            while (c) {
                if (strcmp(c->id, item.container_id) == 0) {
                    strncpy(log_path, c->log_path, sizeof(log_path) - 1);
                    break;
                }
                c = c->next;
            }
            pthread_mutex_unlock(&ctx->metadata_lock);

            if (log_path[0]) {
                fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd >= 0) {
                    strncpy(log_files[num_files].container_id,
                            item.container_id,
                            sizeof(log_files[num_files].container_id) - 1);
                    log_files[num_files].fd = fd;
                    num_files++;
                }
            }
        }

        if (fd >= 0 && item.length > 0)
            (void)write(fd, item.data, item.length);
    }

    for (i = 0; i < num_files; i++) {
        if (log_files[i].fd >= 0)
            close(log_files[i].fd);
    }
    return NULL;
}

/* ---------------------------------------------------------------
 * Producer Thread (one per container pipe)
 * --------------------------------------------------------------- */

static void *producer_thread(void *arg)
{
    producer_args_t *pargs = (producer_args_t *)arg;
    log_item_t item;
    ssize_t nr;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, pargs->container_id,
            sizeof(item.container_id) - 1);

    while ((nr = read(pargs->pipe_fd, item.data, sizeof(item.data))) > 0) {
        item.length = (size_t)nr;
        bounded_buffer_push(pargs->log_buffer, &item);
        memset(item.data, 0, sizeof(item.data));
        item.length = 0;
    }

    close(pargs->pipe_fd);
    free(pargs);
    return NULL;
}

/* ---------------------------------------------------------------
 * Clone Child Entry Point
 * --------------------------------------------------------------- */

int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    char *exec_argv[2];
    int stdin_fd;
    int fd;

    /* Redirect stdout/stderr to logging pipe */
    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0 ||
        dup2(cfg->log_write_fd, STDERR_FILENO) < 0)
        _exit(1);

    /* Redirect stdin from /dev/null */
    stdin_fd = open("/dev/null", O_RDONLY);
    if (stdin_fd >= 0) {
        dup2(stdin_fd, STDIN_FILENO);
        close(stdin_fd);
    }

    /* Close all inherited fds above 2 */
    for (fd = 3; fd < 1024; fd++)
        close(fd);

    /* Set container hostname in the new UTS namespace */
    sethostname(cfg->id, strlen(cfg->id));

    /* Pivot into the container's private rootfs (mount namespace) */
    if (chroot(cfg->rootfs) != 0) {
        fprintf(stderr, "chroot(%s): %s\n", cfg->rootfs, strerror(errno));
        _exit(1);
    }
    if (chdir("/") != 0) {
        fprintf(stderr, "chdir(/): %s\n", strerror(errno));
        _exit(1);
    }

    /* Mount /proc so ps/top work inside the container */
    mkdir("/proc", 0755);
    (void)mount("proc", "/proc", "proc", 0, NULL);

    /* Apply scheduling priority */
    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    /* Execute requested command */
    exec_argv[0] = cfg->command;
    exec_argv[1] = NULL;
    execv(cfg->command, exec_argv);

    fprintf(stderr, "execv(%s): %s\n", cfg->command, strerror(errno));
    _exit(127);
}

/* ---------------------------------------------------------------
 * Monitor ioctl helpers
 * --------------------------------------------------------------- */

int register_with_monitor(int monitor_fd, const char *container_id,
                          pid_t host_pid, unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid              = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id,
                            pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ---------------------------------------------------------------
 * Supervisor internals
 * --------------------------------------------------------------- */

/* Caller must hold metadata_lock */
static container_record_t *find_container_locked(supervisor_ctx_t *ctx,
                                                  const char *id)
{
    container_record_t *c = ctx->containers;
    while (c) {
        if (strcmp(c->id, id) == 0)
            return c;
        c = c->next;
    }
    return NULL;
}

/* Reap all exited children; update metadata and signal waiters.
   Called from the main loop (process context, not signal handler). */
static void handle_sigchld_safe(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        container_record_t *c;

        pthread_mutex_lock(&ctx->metadata_lock);
        c = ctx->containers;
        while (c) {
            if (c->host_pid == pid) {
                if (WIFEXITED(status)) {
                    c->exit_code   = WEXITSTATUS(status);
                    c->exit_signal = 0;
                    c->state = c->stop_requested
                               ? CONTAINER_STOPPED : CONTAINER_EXITED;
                } else if (WIFSIGNALED(status)) {
                    c->exit_signal = WTERMSIG(status);
                    c->exit_code   = 128 + c->exit_signal;
                    if (c->stop_requested)
                        c->state = CONTAINER_STOPPED;
                    else if (c->exit_signal == SIGKILL)
                        c->state = CONTAINER_KILLED;
                    else
                        c->state = CONTAINER_EXITED;
                }
                if (ctx->monitor_fd >= 0)
                    unregister_from_monitor(ctx->monitor_fd, c->id, pid);
                break;
            }
            c = c->next;
        }
        pthread_cond_broadcast(&ctx->metadata_changed);
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

/* Launch a container: create pipe, clone with new namespaces,
   start producer thread, register with kernel monitor. */
static pid_t launch_container(supervisor_ctx_t *ctx,
                               const control_request_t *req)
{
    int pipefd[2];
    char *stack;
    child_config_t *cfg;
    container_record_t *rec;
    pid_t pid;
    producer_args_t *pargs;
    pthread_t producer_tid;

    /* Reject duplicate active container IDs */
    pthread_mutex_lock(&ctx->metadata_lock);
    {
        container_record_t *existing =
            find_container_locked(ctx, req->container_id);
        if (existing && (existing->state == CONTAINER_RUNNING ||
                         existing->state == CONTAINER_STARTING)) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            fprintf(stderr, "Container %s is already running\n",
                    req->container_id);
            return -1;
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }
    /* Read end is for supervisor only; close it in children via CLOEXEC */
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);

    rec = calloc(1, sizeof(*rec));
    if (!rec) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    strncpy(rec->id, req->container_id, sizeof(rec->id) - 1);
    rec->state            = CONTAINER_STARTING;
    rec->started_at       = time(NULL);
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    mkdir(LOG_DIR, 0755);
    snprintf(rec->log_path, sizeof(rec->log_path),
             "%s/%s.log", LOG_DIR, req->container_id);

    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(rec);
        return -1;
    }
    strncpy(cfg->id,      req->container_id, sizeof(cfg->id) - 1);
    strncpy(cfg->rootfs,  req->rootfs,       sizeof(cfg->rootfs) - 1);
    strncpy(cfg->command, req->command,      sizeof(cfg->command) - 1);
    cfg->nice_value   = req->nice_value;
    cfg->log_write_fd = pipefd[1];

    stack = malloc(STACK_SIZE);
    if (!stack) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(cfg);
        free(rec);
        return -1;
    }

    pid = clone(child_fn, stack + STACK_SIZE,
                CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                cfg);

    /* Parent's copies of stack and cfg are independent after clone() */
    free(stack);
    free(cfg);

    if (pid < 0) {
        perror("clone");
        close(pipefd[0]);
        close(pipefd[1]);
        free(rec);
        return -1;
    }

    /* Supervisor closes the write end; child owns it via dup2 */
    close(pipefd[1]);

    rec->host_pid = pid;
    rec->state    = CONTAINER_RUNNING;

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next       = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Register with kernel monitor (best-effort) */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, req->container_id, pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    /* Start producer thread to drain the container's pipe */
    pargs = malloc(sizeof(*pargs));
    if (pargs) {
        pargs->pipe_fd    = pipefd[0];
        pargs->log_buffer = &ctx->log_buffer;
        strncpy(pargs->container_id, req->container_id,
                sizeof(pargs->container_id) - 1);
        if (pthread_create(&producer_tid, NULL, producer_thread, pargs) != 0) {
            free(pargs);
            close(pipefd[0]);
        } else {
            pthread_detach(producer_tid);
        }
    } else {
        close(pipefd[0]);
    }

    return pid;
}

/* ---------------------------------------------------------------
 * Per-command handlers (run inside a per-client thread)
 * --------------------------------------------------------------- */

static void send_response(int fd, const control_response_t *resp)
{
    (void)write(fd, resp, sizeof(*resp));
}

static void handle_start(supervisor_ctx_t *ctx, const control_request_t *req,
                         int client_fd)
{
    control_response_t resp;
    pid_t pid;

    memset(&resp, 0, sizeof(resp));
    pid = launch_container(ctx, req);
    if (pid < 0) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 "Failed to start container %s", req->container_id);
    } else {
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message),
                 "Container %s started (pid=%d)", req->container_id, (int)pid);
    }
    send_response(client_fd, &resp);
}

static void handle_run(supervisor_ctx_t *ctx, const control_request_t *req,
                       int client_fd)
{
    control_response_t resp;
    pid_t pid;
    container_record_t *c;

    memset(&resp, 0, sizeof(resp));
    pid = launch_container(ctx, req);
    if (pid < 0) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 "Failed to start container %s", req->container_id);
        send_response(client_fd, &resp);
        return;
    }

    /* Block until the container reaches a terminal state */
    pthread_mutex_lock(&ctx->metadata_lock);
    while (1) {
        c = find_container_locked(ctx, req->container_id);
        if (!c || c->state == CONTAINER_STOPPED ||
            c->state == CONTAINER_KILLED  ||
            c->state == CONTAINER_EXITED)
            break;
        pthread_cond_wait(&ctx->metadata_changed, &ctx->metadata_lock);
    }
    if (c) {
        resp.status = c->exit_code;
        snprintf(resp.message, sizeof(resp.message),
                 "Container %s exited: state=%s exit_code=%d signal=%d",
                 req->container_id, state_to_string(c->state),
                 c->exit_code, c->exit_signal);
    } else {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 "Container %s: record missing", req->container_id);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
    send_response(client_fd, &resp);
}

static void handle_ps(supervisor_ctx_t *ctx, int client_fd)
{
    control_response_t resp;
    char buf[8192];
    int len = 0;
    container_record_t *c;

    memset(&resp, 0, sizeof(resp));
    pthread_mutex_lock(&ctx->metadata_lock);
    len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                    "%-16s %-8s %-12s %-10s %-10s %-10s\n",
                    "ID", "PID", "STATE", "EXIT_CODE",
                    "SOFT_MIB", "HARD_MIB");
    c = ctx->containers;
    while (c && len < (int)sizeof(buf) - 128) {
        len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                        "%-16s %-8d %-12s %-10d %-10lu %-10lu\n",
                        c->id, (int)c->host_pid, state_to_string(c->state),
                        c->exit_code,
                        c->soft_limit_bytes >> 20,
                        c->hard_limit_bytes >> 20);
        c = c->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    resp.status      = 0;
    resp.payload_len = (size_t)len;
    snprintf(resp.message, sizeof(resp.message), "OK");
    send_response(client_fd, &resp);
    (void)write(client_fd, buf, (size_t)len);
}

static void handle_logs(supervisor_ctx_t *ctx, const control_request_t *req,
                        int client_fd)
{
    control_response_t resp;
    char log_path[PATH_MAX];
    int log_fd;
    struct stat st;
    char ibuf[4096];
    ssize_t nr;

    memset(&resp, 0, sizeof(resp));
    log_path[0] = '\0';

    pthread_mutex_lock(&ctx->metadata_lock);
    {
        container_record_t *c = find_container_locked(ctx, req->container_id);
        if (c)
            strncpy(log_path, c->log_path, sizeof(log_path) - 1);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (!log_path[0]) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 "Container %s not found", req->container_id);
        send_response(client_fd, &resp);
        return;
    }

    log_fd = open(log_path, O_RDONLY);
    if (log_fd < 0) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 "Log file not found: %s", log_path);
        send_response(client_fd, &resp);
        return;
    }

    if (fstat(log_fd, &st) < 0)
        st.st_size = 0;

    resp.status      = 0;
    resp.payload_len = (size_t)st.st_size;
    snprintf(resp.message, sizeof(resp.message), "OK");
    send_response(client_fd, &resp);

    while ((nr = read(log_fd, ibuf, sizeof(ibuf))) > 0)
        (void)write(client_fd, ibuf, (size_t)nr);
    close(log_fd);
}

static void handle_stop(supervisor_ctx_t *ctx, const control_request_t *req,
                        int client_fd)
{
    control_response_t resp;
    container_record_t *c;

    memset(&resp, 0, sizeof(resp));
    pthread_mutex_lock(&ctx->metadata_lock);
    c = find_container_locked(ctx, req->container_id);
    if (!c || (c->state != CONTAINER_RUNNING &&
               c->state != CONTAINER_STARTING)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message),
                 c ? "Container %s is not running" : "Container %s not found",
                 req->container_id);
        send_response(client_fd, &resp);
        return;
    }
    c->stop_requested = 1;
    kill(c->host_pid, SIGTERM);
    pthread_mutex_unlock(&ctx->metadata_lock);

    resp.status = 0;
    snprintf(resp.message, sizeof(resp.message),
             "SIGTERM sent to container %s", req->container_id);
    send_response(client_fd, &resp);
}

/* ---------------------------------------------------------------
 * Client handler thread
 * --------------------------------------------------------------- */

static void *client_handler_thread(void *arg)
{
    client_thread_args_t *cargs = (client_thread_args_t *)arg;
    supervisor_ctx_t *ctx       = cargs->ctx;
    int client_fd               = cargs->client_fd;
    control_request_t req;
    control_response_t resp;

    free(cargs);

    if (read(client_fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        close(client_fd);
        return NULL;
    }

    switch (req.kind) {
    case CMD_START:
        handle_start(ctx, &req, client_fd);
        break;
    case CMD_RUN:
        handle_run(ctx, &req, client_fd);
        break;
    case CMD_PS:
        handle_ps(ctx, client_fd);
        break;
    case CMD_LOGS:
        handle_logs(ctx, &req, client_fd);
        break;
    case CMD_STOP:
        handle_stop(ctx, &req, client_fd);
        break;
    default:
        memset(&resp, 0, sizeof(resp));
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "Unknown command");
        send_response(client_fd, &resp);
        break;
    }

    close(client_fd);
    return NULL;
}

/* ---------------------------------------------------------------
 * Supervisor main loop
 * --------------------------------------------------------------- */

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;
    int rc;

    (void)rootfs;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    rc = pthread_cond_init(&ctx.metadata_changed, NULL);
    if (rc != 0) {
        errno = rc; perror("pthread_cond_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc; perror("bounded_buffer_init");
        pthread_cond_destroy(&ctx.metadata_changed);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    mkdir(LOG_DIR, 0755);

    /* Open kernel monitor device (best-effort) */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "Warning: /dev/container_monitor unavailable"
                        " -- kernel monitor disabled\n");

    /* Self-pipe for signal delivery */
    if (pipe(g_sig_pipe) < 0) { perror("pipe"); return 1; }
    fcntl(g_sig_pipe[1], F_SETFL, O_NONBLOCK);
    fcntl(g_sig_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(g_sig_pipe[1], F_SETFD, FD_CLOEXEC);

    /* Install signal handlers */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = shutdown_handler;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Create UNIX domain socket for CLI control channel */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }
    fcntl(ctx.server_fd, F_SETFD, FD_CLOEXEC);

    unlink(CONTROL_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(ctx.server_fd);
        return 1;
    }
    if (listen(ctx.server_fd, 16) < 0) {
        perror("listen");
        close(ctx.server_fd);
        return 1;
    }

    /* Start logging consumer thread */
    if (pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx) != 0) {
        perror("pthread_create logger");
        close(ctx.server_fd);
        return 1;
    }

    fprintf(stderr, "Supervisor ready. Control socket: %s\n", CONTROL_PATH);

    /* ---- Main event loop ---- */
    while (!ctx.should_stop) {
        fd_set rfds;
        int maxfd;

        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd,  &rfds);
        FD_SET(g_sig_pipe[0],  &rfds);
        maxfd = ctx.server_fd > g_sig_pipe[0]
                ? ctx.server_fd : g_sig_pipe[0];

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(g_sig_pipe[0], &rfds)) {
            char buf[64];
            ssize_t n = read(g_sig_pipe[0], buf, sizeof(buf));
            ssize_t k;
            for (k = 0; k < n; k++) {
                if (buf[k] == 'C')
                    handle_sigchld_safe(&ctx);
                else if (buf[k] == 'S')
                    ctx.should_stop = 1;
            }
        }

        if (!ctx.should_stop && FD_ISSET(ctx.server_fd, &rfds)) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd >= 0) {
                client_thread_args_t *cargs = malloc(sizeof(*cargs));
                pthread_t tid;
                if (cargs) {
                    cargs->ctx       = &ctx;
                    cargs->client_fd = client_fd;
                    if (pthread_create(&tid, NULL,
                                       client_handler_thread, cargs) == 0) {
                        pthread_detach(tid);
                    } else {
                        free(cargs);
                        close(client_fd);
                    }
                } else {
                    close(client_fd);
                }
            }
        }
    }

    /* ---- Graceful shutdown ---- */
    fprintf(stderr, "Supervisor shutting down...\n");

    /* Send SIGTERM to all running containers */
    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *c = ctx.containers;
        while (c) {
            if (c->state == CONTAINER_RUNNING ||
                c->state == CONTAINER_STARTING) {
                c->stop_requested = 1;
                kill(c->host_pid, SIGTERM);
            }
            c = c->next;
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Wait up to STOP_TIMEOUT_SEC for containers to exit */
    {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += STOP_TIMEOUT_SEC;

        pthread_mutex_lock(&ctx.metadata_lock);
        while (1) {
            int all_done = 1;
            container_record_t *c = ctx.containers;
            while (c) {
                if (c->state == CONTAINER_RUNNING ||
                    c->state == CONTAINER_STARTING) {
                    all_done = 0;
                    break;
                }
                c = c->next;
            }
            if (all_done) break;

            if (pthread_cond_timedwait(&ctx.metadata_changed,
                                       &ctx.metadata_lock,
                                       &deadline) == ETIMEDOUT) {
                /* Force-kill anything still alive */
                c = ctx.containers;
                while (c) {
                    if (c->state == CONTAINER_RUNNING ||
                        c->state == CONTAINER_STARTING)
                        kill(c->host_pid, SIGKILL);
                    c = c->next;
                }
                break;
            }
        }
        pthread_mutex_unlock(&ctx.metadata_lock);
    }

    /* Reap remaining zombies */
    {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0)
            ;
    }

    /* Drain and join the logging pipeline */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    /* Cleanup resources */
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    close(g_sig_pipe[0]);
    close(g_sig_pipe[1]);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *c = ctx.containers;
        while (c) {
            container_record_t *next = c->next;
            free(c);
            c = next;
        }
        ctx.containers = NULL;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    pthread_cond_destroy(&ctx.metadata_changed);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);

    fprintf(stderr, "Supervisor exited cleanly.\n");
    return 0;
}

/* ---------------------------------------------------------------
 * CLI client -- send a request and print the response
 * --------------------------------------------------------------- */

static int send_control_request(const control_request_t *req)
{
    int sock_fd;
    struct sockaddr_un addr;
    control_response_t resp;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor at %s: %s\n",
                CONTROL_PATH, strerror(errno));
        close(sock_fd);
        return 1;
    }

    if (write(sock_fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write");
        close(sock_fd);
        return 1;
    }

    if (read(sock_fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
        perror("read");
        close(sock_fd);
        return 1;
    }

    printf("%s\n", resp.message);

    if (resp.payload_len > 0) {
        char *payload = malloc(resp.payload_len + 1);
        if (payload) {
            size_t total = 0;
            while (total < resp.payload_len) {
                ssize_t nr = read(sock_fd, payload + total,
                                  resp.payload_len - total);
                if (nr <= 0) break;
                total += (size_t)nr;
            }
            payload[total] = '\0';
            printf("%s", payload);
            free(payload);
        }
    }

    close(sock_fd);
    return resp.status < 0 ? 1 : 0;
}

/* ---------------------------------------------------------------
 * CLI command handlers
 * --------------------------------------------------------------- */

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

/* cmd_run: blocks until container exits; forwards SIGINT/SIGTERM as stop */
static volatile sig_atomic_t g_run_interrupted = 0;
static char g_run_id[CONTAINER_ID_LEN];

static void run_interrupt_handler(int sig)
{
    (void)sig;
    g_run_interrupted = 1;
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    int sock_fd;
    struct sockaddr_un addr;
    control_response_t resp;
    struct sigaction sa, old_int, old_term;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;

    strncpy(g_run_id, req.container_id, sizeof(g_run_id) - 1);
    g_run_interrupted = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = run_interrupt_handler;
    sigaction(SIGINT,  &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor: %s\n", strerror(errno));
        close(sock_fd);
        return 1;
    }

    if (write(sock_fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        perror("write");
        close(sock_fd);
        return 1;
    }

    /* Poll for response; forward interrupts as stop commands */
    while (1) {
        fd_set rfds;
        struct timeval tv = {1, 0};
        int rc;

        if (g_run_interrupted) {
            control_request_t stop_req;
            memset(&stop_req, 0, sizeof(stop_req));
            stop_req.kind = CMD_STOP;
            strncpy(stop_req.container_id, g_run_id,
                    sizeof(stop_req.container_id) - 1);
            send_control_request(&stop_req);
            g_run_interrupted = 0;
        }

        FD_ZERO(&rfds);
        FD_SET(sock_fd, &rfds);
        rc = select(sock_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) break;

        if (FD_ISSET(sock_fd, &rfds)) {
            ssize_t nr = read(sock_fd, &resp, sizeof(resp));
            if (nr == (ssize_t)sizeof(resp)) {
                printf("%s\n", resp.message);
                if (resp.payload_len > 0) {
                    char *payload = malloc(resp.payload_len + 1);
                    if (payload) {
                        size_t total = 0;
                        while (total < resp.payload_len) {
                            nr = read(sock_fd, payload + total,
                                      resp.payload_len - total);
                            if (nr <= 0) break;
                            total += (size_t)nr;
                        }
                        payload[total] = '\0';
                        printf("%s", payload);
                        free(payload);
                    }
                }
                close(sock_fd);
                sigaction(SIGINT,  &old_int,  NULL);
                sigaction(SIGTERM, &old_term, NULL);
                return resp.status < 0 ? 1 : 0;
            }
            break;
        }
    }

    close(sock_fd);
    sigaction(SIGINT,  &old_int,  NULL);
    sigaction(SIGTERM, &old_term, NULL);
    return 1;
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

/* ---------------------------------------------------------------
 * main
 * --------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }
    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
