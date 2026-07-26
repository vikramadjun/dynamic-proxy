#include "common.h"

static FILE *g_log_file = NULL;
static CRITICAL_SECTION g_log_lock;
static int g_log_lock_ready = 0;

void log_init(const char *path) {
    if (!g_log_lock_ready) {
        InitializeCriticalSection(&g_log_lock);
        g_log_lock_ready = 1;
    }
    if (path && path[0]) {
        g_log_file = fopen(path, "a");
    }
}

void log_msg(const char *fmt, ...) {
    char timebuf[32];
    time_t t = time(NULL);
    struct tm *lt = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", lt);

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (g_log_lock_ready) EnterCriticalSection(&g_log_lock);

    fprintf(stdout, "[%s] %s\n", timebuf, msg);
    fflush(stdout);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s\n", timebuf, msg);
        fflush(g_log_file);
    }

    if (g_log_lock_ready) LeaveCriticalSection(&g_log_lock);
}
