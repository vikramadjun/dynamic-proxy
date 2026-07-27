#include "common.h"

static const char *HEALTH_CHECK_HOSTS[] = {
    "www.msftconnecttest.com",
    "detectportal.firefox.com"
};
static const int HEALTH_CHECK_HOST_COUNT = 2;

static int try_one_check(const Route *route, const char *host, int port) {
    SOCKET s = connect_via_route(route, host, port);
    if (s == INVALID_SOCKET) return 0;

    char req[256];
    int len = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (!send_all(s, req, len)) { closesocket(s); return 0; }

    char buf[512];
    int n = recv_some(s, buf, sizeof(buf) - 1, 5000);
    closesocket(s);

    if (n > 0) {
        buf[n] = 0;
        if (strncmp(buf, "HTTP/1.", 7) == 0) return 1;
    }
    return 0;
}

int check_route_alive(const Route *route, const Config *cfg) {
    if (cfg->check_host[0]) {
        return try_one_check(route, cfg->check_host, cfg->check_port);
    }
    for (int i = 0; i < HEALTH_CHECK_HOST_COUNT; i++) {
        if (try_one_check(route, HEALTH_CHECK_HOSTS[i], 80)) return 1;
    }
    return 0;
}

static const char *route_kind_name(RouteType t) {
    if (t == ROUTE_DIRECT) return "direct";
    if (t == ROUTE_SOCKS5) return "SOCKS5";
    return "HTTP(S)";
}

void routemanager_init(RouteManager *rm, Config *cfg, const char *config_path, const CliOverrides *overrides) {
    rm->cfg = cfg;
    InitializeCriticalSection(&rm->lock);
    rm->active_index = -2;
    rm->running = 1;
    rm->listen_generation = 0;

    strncpy(rm->config_path, config_path, sizeof(rm->config_path) - 1);
    rm->config_path[sizeof(rm->config_path) - 1] = 0;
    rm->overrides = *overrides;

    struct stat st;
    rm->config_mtime = (stat(config_path, &st) == 0) ? st.st_mtime : 0;
}

int routemanager_get_active(RouteManager *rm, Route *out_route) {
    int idx;
    EnterCriticalSection(&rm->lock);
    idx = rm->active_index;
    if (idx >= 0) *out_route = rm->cfg->routes[idx];
    LeaveCriticalSection(&rm->lock);
    return idx;
}

static void scan_for_active(RouteManager *rm) {
    Config *cfg;
    EnterCriticalSection(&rm->lock);
    cfg = rm->cfg;
    LeaveCriticalSection(&rm->lock);

    for (int i = 0; i < cfg->route_count; i++) {
        if (check_route_alive(&cfg->routes[i], cfg)) {
            EnterCriticalSection(&rm->lock);
            int changed = (rm->active_index != i);
            rm->active_index = i;
            LeaveCriticalSection(&rm->lock);
            if (changed) {
                log_msg("Active route: route%d (%s)", i + 1, route_kind_name(cfg->routes[i].type));
            }
            return;
        }
    }
    EnterCriticalSection(&rm->lock);
    int changed = (rm->active_index != -1);
    rm->active_index = -1;
    LeaveCriticalSection(&rm->lock);
    if (changed) {
        log_msg("No route is working - new connections will be refused");
    }
}

/* Re-reads the .ini if its mtime moved. Swaps in a whole new Config so that
   connections already relaying keep the Route copy they grabbed earlier -
   nothing is disrupted mid-flight. Bumps listen_generation only if the
   [listen] section actually changed, so main's accept loop knows to rebind. */
static void check_config_reload(RouteManager *rm) {
    struct stat st;
    if (stat(rm->config_path, &st) != 0) return;
    if (st.st_mtime == rm->config_mtime) return;

    rm->config_mtime = st.st_mtime;

    Config *newcfg = (Config*)malloc(sizeof(Config));
    if (!newcfg) return;
    config_defaults(newcfg);

    if (!config_load(rm->config_path, newcfg)) {
        log_msg("Failed to reload %s - keeping previous settings", rm->config_path);
        free(newcfg);
        return;
    }
    apply_cli_overrides(newcfg, &rm->overrides);

    EnterCriticalSection(&rm->lock);
    Config *oldcfg = rm->cfg;
    int listen_changed = (strcmp(newcfg->listen_bind, oldcfg->listen_bind) != 0 ||
                           newcfg->listen_port != oldcfg->listen_port);
    rm->cfg = newcfg;
    rm->active_index = -2; /* force a fresh scan against the new route list */
    if (listen_changed) rm->listen_generation++;
    LeaveCriticalSection(&rm->lock);

    log_msg("Settings reloaded from %s (%d routes)", rm->config_path, newcfg->route_count);
    if (listen_changed) {
        log_msg("Listen address/port changed: %s:%d -> %s:%d",
                oldcfg->listen_bind, oldcfg->listen_port, newcfg->listen_bind, newcfg->listen_port);
    }
    /* oldcfg is intentionally not freed: it's a small fixed-size struct, and
       connections mid-relay only hold a Route copy, never the Config pointer,
       so this can't be a use-after-free - just a harmless, bounded leak per reload. */
}

DWORD WINAPI routemanager_thread(LPVOID param) {
    RouteManager *rm = (RouteManager*)param;

    log_msg("Initial route check...");
    scan_for_active(rm);

    int fail_count = 0;
    int since_health = 0;
    int since_config_check = 0;

    while (rm->running) {
        Sleep(1000);
        since_health++;
        since_config_check++;

        if (since_config_check >= 2) {
            since_config_check = 0;
            check_config_reload(rm); /* may reset active_index to -2 */
        }

        Config *cfg;
        int idx;
        EnterCriticalSection(&rm->lock);
        cfg = rm->cfg;
        idx = rm->active_index;
        LeaveCriticalSection(&rm->lock);

        if (since_health >= cfg->health_interval_sec) {
            since_health = 0;

            if (idx < 0) {
                scan_for_active(rm);
                fail_count = 0;
            } else if (check_route_alive(&cfg->routes[idx], cfg)) {
                fail_count = 0;
            } else {
                fail_count++;
                log_msg("route%d check failed (%d/%d)", idx + 1, fail_count, cfg->health_fail_threshold);
                if (fail_count >= cfg->health_fail_threshold) {
                    log_msg("route%d is unavailable, searching for a working route by priority", idx + 1);
                    fail_count = 0;
                    scan_for_active(rm);
                }
            }
        } else if (idx == -2) {
            /* a reload just happened - don't wait out the rest of the old
               health-check interval before validating the new route list */
            scan_for_active(rm);
            fail_count = 0;
            since_health = 0;
        }
    }
    return 0;
}
