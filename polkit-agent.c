#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#define AGENT_OBJ_PATH  "/org/freedesktop/PolicyKit1/AuthenticationAgent"
#define AGENT_IFACE     "org.freedesktop.PolicyKit1.AuthenticationAgent"
#define AUTHORITY_NAME  "org.freedesktop.PolicyKit1"
#define AUTHORITY_OBJ   "/org/freedesktop/PolicyKit1/Authority"
#define AUTHORITY_IFACE "org.freedesktop.PolicyKit1.Authority"
#define HELPER_PATH     "/usr/lib/polkit-1/polkit-agent-helper-1"

static DBusConnection *g_bus = NULL;
static volatile sig_atomic_t g_running = 1;
static pid_t g_auth_child = 0;
static DBusMessage *g_pending_msg = NULL;

#include "log.h"
log_level_t g_log_level = LL_WARN;
const char *g_log_prefix = "polkit-agent";

static void sigterm_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static DBusConnection *connect_system_bus(void) {
    DBusError err;
    dbus_error_init(&err);
    DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!conn) {
        log_error("cannot connect to system bus: %s", err.message);
        dbus_error_free(&err);
        return NULL;
    }
    dbus_connection_set_exit_on_disconnect(conn, FALSE);
    return conn;
}

static int system_call(DBusMessage *call) {
    DBusError err;
    dbus_error_init(&err);
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_bus, call, -1, &err);
    if (!reply) {
        log_warn("D-Bus call failed: %s", err.message);
        dbus_error_free(&err);
        return -1;
    }
    dbus_message_unref(reply);
    return 0;
}

/* Determine the login session this process belongs to, the same way polkitd
 * does (sd_pid_get_session: cgroup membership in session-N.scope). Must match
 * polkitd exactly or RegisterAuthenticationAgent is rejected with
 * "Passed session and the session the caller is in differs". A process not in
 * any session scope (e.g. launched from the user systemd manager) yields NULL
 * here - and polkitd agrees it has no session, so registration is impossible. */
static char *get_session_id(void) {
    FILE *cg = fopen("/proc/self/cgroup", "r");
    if (!cg) return NULL;
    char line[512];
    while (fgets(line, sizeof(line), cg)) {
        char *p = strstr(line, "session-");
        if (p) {
            char *s = strchr(p, '.');
            if (s && strncmp(s, ".scope", 6) == 0) {
                *s = '\0';
                p += 8;
                fclose(cg);
                return strdup(p);
            }
        }
    }
    fclose(cg);
    return NULL;
}

static void append_subject(DBusMessageIter *iter, const char *session_id) {
    DBusMessageIter st, arr, de, var;
    dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &st);
    const char *type = "unix-session";
    dbus_message_iter_append_basic(&st, DBUS_TYPE_STRING, &type);
    dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "{sv}", &arr);
    {
        const char *k = "session-id";
        dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &de);
        dbus_message_iter_append_basic(&de, DBUS_TYPE_STRING, &k);
        dbus_message_iter_open_container(&de, DBUS_TYPE_VARIANT, "s", &var);
        dbus_message_iter_append_basic(&var, DBUS_TYPE_STRING, &session_id);
        dbus_message_iter_close_container(&de, &var);
        dbus_message_iter_close_container(&arr, &de);
    }
    dbus_message_iter_close_container(&st, &arr);
    dbus_message_iter_close_container(iter, &st);
}

static void send_reply(DBusConnection *conn, DBusMessage *msg) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
    }
}

static void send_error(DBusConnection *conn, DBusMessage *msg,
                        const char *name, const char *text) {
    DBusMessage *err = dbus_message_new_error(msg, name, text);
    if (err) {
        dbus_connection_send(conn, err, NULL);
        dbus_connection_flush(conn);
        dbus_message_unref(err);
    }
}

static int
read_line(int fd, char *buf, size_t bufsz) {
    size_t i = 0;
    while (i < bufsz - 1) {
        char c;
        int n = read(fd, &c, 1);
        if (n <= 0) {
            buf[i] = '\0';
            return (i > 0) ? (int)i : -1;
        }
        if (c == '\n') {
            buf[i] = '\0';
            return (int)i;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (int)i;
}

static int
connect_helper_socket(void) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/polkit/agent-helper.socket",
            sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void
run_auth_session(const char *cookie, const char *username, uid_t uid, const char *action_id,
                  const char *prompt_path) {
    int sock = connect_helper_socket();
    if (sock < 0) {
        log_error("cannot connect to helper socket");
        _exit(1);
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    write(sock, username, strlen(username));
    write(sock, "\n", 1);
    write(sock, cookie, strlen(cookie));
    write(sock, "\n", 1);

    char line[4096];

    while (read_line(sock, line, sizeof(line)) > 0) {
        if (strncmp(line, "PAM_PROMPT_ECHO_OFF ", 20) == 0) {
            const char *msg = line + 20;
            int prompt_pipe[2];
            if (pipe(prompt_pipe) < 0) break;

            pid_t prompt_pid = fork();
            if (prompt_pid < 0) { close(prompt_pipe[0]); close(prompt_pipe[1]); break; }

            if (prompt_pid == 0) {
                close(prompt_pipe[0]);
                dup2(prompt_pipe[1], STDOUT_FILENO);
                close(prompt_pipe[1]);

                execlp(prompt_path, prompt_path,
                       "--message", msg,
                       "--user", username,
                       (char *)NULL);
                _exit(127);
            }

            close(prompt_pipe[1]);
            char pwbuf[4096] = {0};
            int n = read(prompt_pipe[0], pwbuf, sizeof(pwbuf) - 1);
            close(prompt_pipe[0]);

            if (n <= 0) {
                close(sock);
                kill(prompt_pid, SIGTERM);
                waitpid(prompt_pid, NULL, 0); /* Explicitly reap to prevent future zombie leaks */
                _exit(1);
            }
            if (pwbuf[n - 1] == '\n') pwbuf[n - 1] = '\0';
            
            write(sock, pwbuf, strlen(pwbuf));
            write(sock, "\n", 1);

            int st;
            waitpid(prompt_pid, &st, 0);
        } else if (strcmp(line, "SUCCESS") == 0) {
            log_debug("auth OK for user %s (action %s)", username, action_id);
            close(sock);
            _exit(0);
        } else if (strncmp(line, "ERROR ", 6) == 0) {
            log_debug("auth err for user %s (action %s): %s", username, action_id, line + 6);
            close(sock);
            _exit(1);
        }
    }

    log_warn("helper socket closed unexpectedly");
    close(sock);
    _exit(1);
}

static DBusHandlerResult
agent_msg_handler(DBusConnection *conn, DBusMessage *msg, void *user_data) {
    (void)conn;
    const char *prompt_path = (const char *)user_data;

    if (dbus_message_is_method_call(msg, AGENT_IFACE, "BeginAuthentication")) {
        if (g_auth_child > 0) {
            send_error(conn, msg,
                "org.freedesktop.PolicyKit1.Error.Failed", "Auth in progress");
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        DBusMessageIter args;
        if (!dbus_message_iter_init(msg, &args))
            return DBUS_HANDLER_RESULT_HANDLED;

        char *action_id = NULL, *cookie = NULL;
        int argn = 0;
        while (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_INVALID) {
            if (argn == 0 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&args, &action_id);
            else if (argn == 4 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&args, &cookie);
            argn++;
            dbus_message_iter_next(&args);
        }

        if (!cookie) {
            send_error(g_bus, msg, DBUS_ERROR_INVALID_ARGS, "Missing cookie");
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        uid_t uid = (uid_t)-1;
        {
            DBusMessageIter a2;
            dbus_message_iter_init(msg, &a2);
            int i = 0;
            while (i < 5 && dbus_message_iter_get_arg_type(&a2) != DBUS_TYPE_INVALID) {
                dbus_message_iter_next(&a2); i++;
            }
            if (dbus_message_iter_get_arg_type(&a2) == DBUS_TYPE_ARRAY) {
                DBusMessageIter id_arr;
                dbus_message_iter_recurse(&a2, &id_arr);
                while (dbus_message_iter_get_arg_type(&id_arr) == DBUS_TYPE_STRUCT) {
                    DBusMessageIter id_st;
                    dbus_message_iter_recurse(&id_arr, &id_st);
                    char *id_type = NULL;
                    if (dbus_message_iter_get_arg_type(&id_st) == DBUS_TYPE_STRING)
                        dbus_message_iter_get_basic(&id_st, &id_type);
                    if (id_type && strcmp(id_type, "unix-user") == 0) {
                        dbus_message_iter_next(&id_st);
                        if (dbus_message_iter_get_arg_type(&id_st) == DBUS_TYPE_ARRAY) {
                            DBusMessageIter at;
                            dbus_message_iter_recurse(&id_st, &at);
                            while (dbus_message_iter_get_arg_type(&at) == DBUS_TYPE_DICT_ENTRY) {
                                DBusMessageIter de;
                                dbus_message_iter_recurse(&at, &de);
                                char *key = NULL;
                                if (dbus_message_iter_get_arg_type(&de) == DBUS_TYPE_STRING)
                                    dbus_message_iter_get_basic(&de, &key);
                                if (key && strcmp(key, "uid") == 0) {
                                    dbus_message_iter_next(&de);
                                    if (dbus_message_iter_get_arg_type(&de) == DBUS_TYPE_VARIANT) {
                                        DBusMessageIter v;
                                        dbus_message_iter_recurse(&de, &v);
                                        if (dbus_message_iter_get_arg_type(&v) == DBUS_TYPE_UINT32) {
                                            dbus_uint32_t u;
                                            dbus_message_iter_get_basic(&v, &u);
                                            uid = (uid_t)u;
                                        }
                                    }
                                }
                                dbus_message_iter_next(&at);
                            }
                        }
                    }
                    dbus_message_iter_next(&id_arr);
                    if (uid != (uid_t)-1) break;
                }
            }
        }

        if (uid == (uid_t)-1) {
            send_error(g_bus, msg,
                "org.freedesktop.PolicyKit1.Error.Failed", "Cannot determine uid");
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        struct passwd *pw = getpwuid(uid);
        if (!pw) {
            send_error(g_bus, msg,
                "org.freedesktop.PolicyKit1.Error.Failed", "Unknown uid");
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        g_pending_msg = dbus_message_ref(msg);

        pid_t child = fork();
        if (child == 0) {
            run_auth_session(cookie, pw->pw_name, uid, action_id ? action_id : "unknown", prompt_path);
            _exit(1);
        } else if (child > 0) {
            g_auth_child = child;
        }

        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if (dbus_message_is_method_call(msg, AGENT_IFACE, "CancelAuthentication")) {
        if (g_auth_child > 0) {
            kill(g_auth_child, SIGTERM);
            waitpid(g_auth_child, NULL, WNOHANG);
            g_auth_child = 0;
            if (g_pending_msg) {
                send_error(conn, g_pending_msg, "org.freedesktop.PolicyKit1.Error.Cancelled", "Cancelled");
                dbus_message_unref(g_pending_msg);
                g_pending_msg = NULL;
            }
        }
        send_reply(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static char *g_session_id = NULL;

static void register_agent(void) {
    DBusMessage *call = dbus_message_new_method_call(
        AUTHORITY_NAME, AUTHORITY_OBJ, AUTHORITY_IFACE,
        "RegisterAuthenticationAgent");
    if (!call) { log_error("out of memory"); return; }

    const char *locale = getenv("LANG");
    if (!locale || !*locale) locale = "C";
    const char *obj_path = AGENT_OBJ_PATH;

    DBusMessageIter iter;
    dbus_message_iter_init_append(call, &iter);
    append_subject(&iter, g_session_id);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &locale);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &obj_path);

    if (system_call(call) == 0)
        log_debug("registered (session=%s)", g_session_id);
    dbus_message_unref(call);
}

static void unregister_agent(void) {
    DBusMessage *call = dbus_message_new_method_call(
        AUTHORITY_NAME, AUTHORITY_OBJ, AUTHORITY_IFACE,
        "UnregisterAuthenticationAgent");
    if (!call) return;

    const char *obj_path = AGENT_OBJ_PATH;
    DBusMessageIter iter;
    dbus_message_iter_init_append(call, &iter);
    append_subject(&iter, g_session_id);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &obj_path);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_bus, call, 1000, &err);
    dbus_message_unref(call);
    if (reply) dbus_message_unref(reply);
    else dbus_error_free(&err);
}

int main(int argc, char **argv) {
    const char *prompt_path = NULL;
    DBusError err;
    dbus_error_init(&err);

#ifndef PROMPT_DEFAULT_PATH
#define PROMPT_DEFAULT_PATH "/usr/lib/polkit-agent-lite/polkit-prompt"
#endif

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0)
            g_log_level = LL_DEBUG;
    }
    
    prompt_path = PROMPT_DEFAULT_PATH;

    g_session_id = get_session_id();
    if (!g_session_id) {
        log_error("cannot determine session ID");
        return 1;
    }

    struct sigaction sa;
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    g_bus = connect_system_bus();
    if (!g_bus) return 1;

    static const DBusObjectPathVTable vtable = {
        .unregister_function = NULL,
        .message_function = agent_msg_handler,
    };
    if (!dbus_connection_try_register_object_path(g_bus, AGENT_OBJ_PATH, &vtable, (void*)prompt_path, &err)) {
        log_error("failed to register object path: %s", err.message);
        dbus_error_free(&err);
        return 1;
    }

    register_agent();
    
    while (g_running) {
        if (!dbus_connection_read_write_dispatch(g_bus, 100)) {
            log_error("system bus disconnected");
            break;
        }

        if (g_auth_child > 0) {
            int st;
            if (waitpid(g_auth_child, &st, WNOHANG) > 0) {
                g_auth_child = 0;
                if (g_pending_msg) {
                    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
                        send_reply(g_bus, g_pending_msg);
                    } else {
                        send_error(g_bus, g_pending_msg, "org.freedesktop.PolicyKit1.Error.Failed", "Authentication failed");
                    }
                    dbus_message_unref(g_pending_msg);
                    g_pending_msg = NULL;
                }
            }
        }
    }

    log_debug("exiting");
    if (g_auth_child > 0) { kill(g_auth_child, SIGTERM); waitpid(g_auth_child, NULL, 0); }
    unregister_agent();
    free(g_session_id);
    dbus_connection_unref(g_bus);
    return 0;
}
