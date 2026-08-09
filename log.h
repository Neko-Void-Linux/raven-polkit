#ifndef POLKIT_AGENT_LITE_LOG_H
#define POLKIT_AGENT_LITE_LOG_H

/*
 * Minimal syslog-style logger for polkit-agent-lite.
 *
 * Output format (single line, tail-friendly):
 *   polkit-agent[1234]: ERROR cannot connect to system bus
 *   polkit-agent[1234]: WARN  auth FAILED for user root (action org.example.x)
 *   polkit-agent[1234]: DEBUG auth OK for user root (action org.example.x)
 *
 * Only two levels reach stderr by default: ERROR and WARN.
 * DEBUG is opt-in at runtime via --debug. There is no INFO level -
 * a small daemon doesn't need four log tiers (lxpolkit uses one).
 *
 * No sensitive data (cookies, passwords, raw PAM payloads) should ever
 * be passed to these macros.
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum {
    LL_ERROR = 0,
    LL_WARN  = 1,
    LL_DEBUG  = 2,
} log_level_t;

/* Set per-process at startup. Default LL_WARN: silent in normal operation. */
extern log_level_t g_log_level;
extern const char *g_log_prefix;

static inline void log_emit(log_level_t lvl, const char *fmt, ...)
{
    if (lvl > g_log_level) return;

    static const char *names[] = {"ERROR", "WARN ", "DEBUG"};
    const char *name = (lvl >= LL_ERROR && lvl <= LL_DEBUG) ? names[lvl] : "????";

    flockfile(stderr);
    fprintf(stderr, "%s[%d]: %s ", g_log_prefix, (int)getpid(), name);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}

#define log_error(...) log_emit(LL_ERROR, __VA_ARGS__)
#define log_warn(...)  log_emit(LL_WARN,  __VA_ARGS__)
#define log_debug(...) log_emit(LL_DEBUG, __VA_ARGS__)

#endif
