#include "common.h"

SOCKET create_and_bind_listen_socket(const Config *cfg) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)cfg->listen_port);
    if (inet_pton(AF_INET, cfg->listen_bind, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 64) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/* The actual proxy: loading config, opening sockets, spinning up the
   health/DNS/client threads, and the accept loop. Used identically whether
   we were started as a normal console program or by the Service Control
   Manager - a service is just this, running headless. */
int run_proxy(const char *config_path, const CliOverrides *overrides) {
    Config cfg;
    config_defaults(&cfg);

    log_init(NULL);
    log_msg("Loading configuration from %s", config_path);

    if (!config_load(config_path, &cfg)) {
        log_msg("Using default settings (file not found or invalid)");
    }
    if (cfg.route_count == 0) {
        cfg.routes[0].type = ROUTE_DIRECT;
        cfg.route_count = 1;
        log_msg("No routes configured - falling back to a direct connection only");
    }
    apply_cli_overrides(&cfg, overrides);

    log_init(cfg.log_path);
    log_msg("=== Proxy v%s starting ===", PROXY_VERSION);
    log_msg("Listening on %s:%d (SOCKS5 + HTTP/HTTPS, auto-detected)", cfg.listen_bind, cfg.listen_port);
    log_msg("Configured routes: %d", cfg.route_count);
    log_msg("Config file: %s (changes are picked up live, no restart needed)", config_path);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_msg("Winsock init failed");
        return 1;
    }

    SOCKET listen_sock = create_and_bind_listen_socket(&cfg);
    if (listen_sock == INVALID_SOCKET) {
        log_msg("bind()/listen() failed on %s:%d (error %d) - is the port already in use?",
                cfg.listen_bind, cfg.listen_port, WSAGetLastError());
        return 1;
    }

    RouteManager rm;
    routemanager_init(&rm, &cfg, config_path, overrides);
    HANDLE health_thread = CreateThread(NULL, 0, routemanager_thread, &rm, 0, NULL);
    if (health_thread) CloseHandle(health_thread);

    HANDLE dns_thread = CreateThread(NULL, 0, dns_server_thread, &rm, 0, NULL);
    if (dns_thread) CloseHandle(dns_thread);

    log_msg("Ready to accept connections.");

    int last_seen_gen = 0;
    for (;;) {
        int gen;
        EnterCriticalSection(&rm.lock);
        gen = rm.listen_generation;
        LeaveCriticalSection(&rm.lock);

        if (gen != last_seen_gen) {
            last_seen_gen = gen;
            Config *newcfg;
            EnterCriticalSection(&rm.lock);
            newcfg = rm.cfg;
            LeaveCriticalSection(&rm.lock);

            SOCKET new_sock = create_and_bind_listen_socket(newcfg);
            if (new_sock != INVALID_SOCKET) {
                closesocket(listen_sock);
                listen_sock = new_sock;
                log_msg("Listening socket reopened: %s:%d", newcfg->listen_bind, newcfg->listen_port);
            } else {
                log_msg("Failed to reopen listening socket on %s:%d (in use?) - staying on previous address",
                        newcfg->listen_bind, newcfg->listen_port);
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_sock, &rfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        struct sockaddr_in cli_addr;
        int cli_len = sizeof(cli_addr);
        SOCKET client = accept(listen_sock, (struct sockaddr*)&cli_addr, &cli_len);
        if (client == INVALID_SOCKET) continue;

        ClientCtx *ctx = (ClientCtx*)malloc(sizeof(ClientCtx));
        ctx->client_sock = client;
        ctx->rm = &rm;

        HANDLE h = CreateThread(NULL, 0, handle_client_thread, ctx, 0, NULL);
        if (h) CloseHandle(h);
    }

    return 0;
}

int main(int argc, char **argv) {
    ServiceArgs sa;
    parse_service_args(argc, argv, &sa);

    char config_path[512];
    CliOverrides overrides;
    parse_cli(argc, argv, config_path, sizeof(config_path), &overrides);
    int cp_explicit = (config_path[0] != 0);

    if (sa.action == SVC_ACTION_INSTALL) {
        return install_service(&sa, config_path, cp_explicit);
    }
    if (sa.action == SVC_ACTION_UNINSTALL) {
        return uninstall_service(&sa);
    }

    if (config_path[0] == 0) {
        if (!get_module_ini_path(config_path, sizeof(config_path))) {
            strncpy(config_path, "proxy.ini", sizeof(config_path) - 1);
        }
    }

    if (sa.is_service) {
        char actual_name[256];
        if (discover_own_service_name(actual_name, sizeof(actual_name))) {
            service_set_context(config_path, &overrides, actual_name);
            return run_as_service(actual_name);
        }
        service_set_context(config_path, &overrides, sa.name);
        return run_as_service(sa.name);
    }

    return run_proxy(config_path, &overrides);
}
