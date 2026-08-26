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
#include <grp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <sys/un.h>

#define AGENT_OBJ_PATH  "/org/freedesktop/PolicyKit1/AuthenticationAgent"
#define AGENT_IFACE     "org.freedesktop.PolicyKit1.AuthenticationAgent"
#define AUTHORITY_NAME  "org.freedesktop.PolicyKit1"
#define AUTHORITY_OBJ   "/org/freedesktop/PolicyKit1/Authority"
#define AUTHORITY_IFACE "org.freedesktop.PolicyKit1.Authority"
#define LINE_BUF_SIZE   4096

static DBusConnection *g_bus = NULL;
static volatile sig_atomic_t g_running = 1;
static pid_t g_auth_child = 0;
static DBusMessage *g_pending_msg = NULL;

#include "log.h"
log_level_t g_log_level = LL_WARN;
const char *g_log_prefix = "raven-polkit-agent";

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
            if (i > 0 && buf[i - 1] == '\r') i--;
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

static int is_lockout_message(const char *msg) {
    if (!msg || !*msg) return 0;
    static const char *patterns[] = {
        "lock", "bloquea", "expire", "expirad", "caducad",
        "disable", "deshabilitad", "desactivad", "denied", "denegad",
        "maximum", "máximo", "max tries", "tally", "faillock"
    };
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if (strcasestr(msg, patterns[i])) return 1;
    }
    return 0;
}

static int
extract_identities(DBusMessageIter *id_arr, char *usernames[], int max_users) {
    int count = 0;
    while (dbus_message_iter_get_arg_type(id_arr) == DBUS_TYPE_STRUCT && count < max_users) {
        DBusMessageIter id_st;
        dbus_message_iter_recurse(id_arr, &id_st);
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
                                struct passwd *pw = getpwuid((uid_t)u);
                                if (pw && pw->pw_name) {
                                    int exists = 0;
                                    for (int j = 0; j < count; j++) {
                                        if (strcmp(usernames[j], pw->pw_name) == 0) {
                                            exists = 1;
                                            break;
                                        }
                                    }
                                    if (!exists && count < max_users) {
                                        usernames[count++] = strdup(pw->pw_name);
                                    }
                                }
                            }
                        }
                    }
                    dbus_message_iter_next(&at);
                }
            }
        } else if (id_type && strcmp(id_type, "unix-group") == 0) {
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
                    if (key && strcmp(key, "gid") == 0) {
                        dbus_message_iter_next(&de);
                        if (dbus_message_iter_get_arg_type(&de) == DBUS_TYPE_VARIANT) {
                            DBusMessageIter v;
                            dbus_message_iter_recurse(&de, &v);
                            if (dbus_message_iter_get_arg_type(&v) == DBUS_TYPE_UINT32) {
                                dbus_uint32_t g;
                                dbus_message_iter_get_basic(&v, &g);
                                struct group *gr = getgrgid((gid_t)g);
                                if (gr && gr->gr_mem) {
                                    for (char **m = gr->gr_mem; *m && count < max_users; m++) {
                                        int exists = 0;
                                        for (int j = 0; j < count; j++) {
                                            if (strcmp(usernames[j], *m) == 0) {
                                                exists = 1;
                                                break;
                                            }
                                        }
                                        if (!exists && count < max_users) {
                                            usernames[count++] = strdup(*m);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    dbus_message_iter_next(&at);
                }
            }
        }
        dbus_message_iter_next(id_arr);
    }
    return count;
}

static void
run_auth_session(const char *cookie, char *usernames[], int user_count,
                 const char *action_id, const char *action_msg, const char *prompt_path) {
    int prompt_sock[2] = {-1, -1};
    pid_t prompt_pid = -1;

    if (user_count <= 0) _exit(1);

    char users_csv[1024] = {0};
    for (int i = 0; i < user_count; i++) {
        if (i > 0) strncat(users_csv, ",", sizeof(users_csv) - strlen(users_csv) - 1);
        strncat(users_csv, usernames[i], sizeof(users_csv) - strlen(users_csv) - 1);
    }

    char current_user[256] = {0};
    strncpy(current_user, usernames[0], sizeof(current_user) - 1);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, prompt_sock) < 0) goto fail;

    prompt_pid = fork();
    if (prompt_pid < 0) {
        close(prompt_sock[0]); close(prompt_sock[1]);
        goto fail;
    }

    if (prompt_pid == 0) {
        close(prompt_sock[0]);
        dup2(prompt_sock[1], STDIN_FILENO);
        dup2(prompt_sock[1], STDOUT_FILENO);
        close(prompt_sock[1]);

        execlp(prompt_path, prompt_path,
                "--message", (action_msg && *action_msg) ? action_msg : "Authentication required",
                "--users", users_csv,
                "--user", current_user,
                (char *)NULL);
        _exit(127);
    }
    close(prompt_sock[1]);

    while (1) {
        int sock = connect_helper_socket();
        if (sock < 0) {
            log_error("cannot connect to helper socket");
            goto fail;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

        write(sock, current_user, strlen(current_user));
        write(sock, "\n", 1);
        write(sock, cookie, strlen(cookie));
        write(sock, "\n", 1);

        char line[LINE_BUF_SIZE];
        int helper_succeeded = 0;
        int had_prompt_echo = 0;
        char pam_error_msg[LINE_BUF_SIZE] = {0};
        int user_switched = 0;

        while (read_line(sock, line, sizeof(line)) > 0) {
            if (strncmp(line, "PAM_PROMPT_ECHO_OFF ", 20) == 0 ||
                strncmp(line, "PAM_PROMPT_ECHO_ON ", 19) == 0) {
                had_prompt_echo = 1;
                int is_echo_off = (strncmp(line, "PAM_PROMPT_ECHO_OFF ", 20) == 0);
                const char *prompt_text = is_echo_off ? (line + 20) : (line + 19);

                char req_buf[LINE_BUF_SIZE + 64];
                snprintf(req_buf, sizeof(req_buf), "REQ %d %s\n", is_echo_off ? 0 : 1, prompt_text);
                write(prompt_sock[0], req_buf, strlen(req_buf));

                char prompt_in[LINE_BUF_SIZE] = {0};
                int n = read_line(prompt_sock[0], prompt_in, sizeof(prompt_in));
                if (n <= 0) {
                    close(sock);
                    goto fail;
                }

                if (prompt_in[0] == 'U' && prompt_in[1] == ' ') {
                    strncpy(current_user, prompt_in + 2, sizeof(current_user) - 1);
                    user_switched = 1;
                    break;
                } else if (prompt_in[0] == 'P' && prompt_in[1] == ' ') {
                    write(sock, prompt_in + 2, strlen(prompt_in + 2));
                    write(sock, "\n", 1);
                } else {
                    write(sock, prompt_in, strlen(prompt_in));
                    write(sock, "\n", 1);
                }
            } else if (strncmp(line, "PAM_ERROR_MSG ", 14) == 0) {
                log_debug("PAM error: %s", line + 14);
                strncpy(pam_error_msg, line + 14, sizeof(pam_error_msg) - 1);
                char m_buf[LINE_BUF_SIZE + 64];
                snprintf(m_buf, sizeof(m_buf), "M %s\n", line + 14);
                write(prompt_sock[0], m_buf, strlen(m_buf));
            } else if (strncmp(line, "PAM_TEXT_INFO ", 14) == 0) {
                log_debug("PAM info: %s", line + 14);
                char m_buf[LINE_BUF_SIZE + 64];
                snprintf(m_buf, sizeof(m_buf), "M %s\n", line + 14);
                write(prompt_sock[0], m_buf, strlen(m_buf));
            } else if (strcmp(line, "SUCCESS") == 0) {
                log_debug("auth OK for user %s (action %s)", current_user, action_id);
                helper_succeeded = 1;
                if (prompt_pid > 0) write(prompt_sock[0], "S\n", 2);
                close(sock);
                _exit(0);
            } else if (strcmp(line, "FAILURE") == 0 || strncmp(line, "ERROR ", 6) == 0) {
                log_debug("auth failed for user %s (action %s)", current_user, action_id);
                break;
            }
        }

        close(sock);

        if (helper_succeeded) {
            _exit(0);
        }

        if (user_switched) {
            continue;
        }

        int is_lockout = 0;
        if (!had_prompt_echo) {
            /* Account is pre-locked or expired; PAM rejected immediately without password prompt */
            is_lockout = 1;
        } else if (is_lockout_message(pam_error_msg)) {
            /* PAM returned explicit lockout message (e.g. from pam_faillock / pam_tally2) */
            is_lockout = 1;
        }

        if (prompt_pid > 0) {
            if (is_lockout) {
                write(prompt_sock[0], "DIS\n", 4);
                char err_buf[LINE_BUF_SIZE + 64];
                if (pam_error_msg[0] != '\0') {
                    snprintf(err_buf, sizeof(err_buf), "E %s\n", pam_error_msg);
                } else {
                    snprintf(err_buf, sizeof(err_buf), "E The account is locked that's why you may not login.\n");
                }
                write(prompt_sock[0], err_buf, strlen(err_buf));

                char switch_buf[LINE_BUF_SIZE];
                while (read_line(prompt_sock[0], switch_buf, sizeof(switch_buf)) > 0) {
                    if (switch_buf[0] == 'U' && switch_buf[1] == ' ') {
                        strncpy(current_user, switch_buf + 2, sizeof(current_user) - 1);
                        user_switched = 1;
                        break;
                    }
                }
                if (user_switched) {
                    continue;
                }
                break;
            } else {
                /* Failed attempt, allow retry (matching xfce-polkit on_session_completed) */
                if (pam_error_msg[0] != '\0' && strcmp(pam_error_msg, "Authentication failure") != 0) {
                    char err_buf[LINE_BUF_SIZE + 64];
                    snprintf(err_buf, sizeof(err_buf), "E %s\n", pam_error_msg);
                    write(prompt_sock[0], err_buf, strlen(err_buf));
                } else {
                    write(prompt_sock[0], "E Failed. Wrong password?\n", 26);
                }
            }
        } else {
            break;
        }
    }

fail:
    if (prompt_pid > 0) {
        kill(prompt_pid, SIGTERM);
        waitpid(prompt_pid, NULL, 0);
    }
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

        char *action_id = NULL, *action_msg = NULL, *cookie = NULL;
        int argn = 0;
        DBusMessageIter id_iter;
        int has_identities = 0;

        while (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_INVALID) {
            if (argn == 0 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&args, &action_id);
            else if (argn == 1 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&args, &action_msg);
            else if (argn == 4 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&args, &cookie);
            else if (argn == 5 && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_ARRAY) {
                dbus_message_iter_recurse(&args, &id_iter);
                has_identities = 1;
            }
            argn++;
            dbus_message_iter_next(&args);
        }

        if (!cookie) {
            send_error(g_bus, msg, DBUS_ERROR_INVALID_ARGS, "Missing cookie");
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        char *usernames[16] = {0};
        int user_count = 0;
        if (has_identities) {
            user_count = extract_identities(&id_iter, usernames, 16);
        }

        if (user_count == 0) {
            struct passwd *pw = getpwuid(getuid());
            if (pw && pw->pw_name) {
                usernames[user_count++] = strdup(pw->pw_name);
            }
            if (getuid() != 0) {
                usernames[user_count++] = strdup("root");
            }
        }

        g_pending_msg = dbus_message_ref(msg);

        pid_t child = fork();
        if (child == 0) {
            run_auth_session(cookie, usernames, user_count, action_id ? action_id : "unknown", action_msg, prompt_path);
            _exit(1);
        } else if (child > 0) {
            g_auth_child = child;
        }

        for (int j = 0; j < user_count; j++) {
            free(usernames[j]);
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
#define PROMPT_DEFAULT_PATH "/usr/lib/raven-polkit/raven-polkit-prompt"
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
