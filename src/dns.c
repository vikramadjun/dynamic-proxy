#include "common.h"

typedef struct {
    RouteManager *rm;
    SOCKET udp_sock;
    struct sockaddr_in client_addr;
    int client_addr_len;
    unsigned char query[2048];
    int query_len;
} DnsQueryCtx;

/* Forwards one DNS query to the upstream resolvers via DNS-over-TCP, tunneled
   through whichever route is currently active (direct/SOCKS5/HTTP) - so DNS
   respects the exact same failover as everything else, and never leaks
   outside the proxy chain.

   Upstreams are tried in order, but "tried" means more than "did it answer" -
   a resolver that replies NXDOMAIN/SERVFAIL/REFUSED (RCODE != 0) genuinely
   doesn't know the name, so we move on to the next upstream too. The first
   real DNS response we get (even an error one) is kept as a fallback, so if
   nobody has a clean answer the client still gets a proper NXDOMAIN back
   instead of silence. */
static void handle_dns_query(DnsQueryCtx *ctx) {
    Config *cfg;
    EnterCriticalSection(&ctx->rm->lock);
    cfg = ctx->rm->cfg;
    LeaveCriticalSection(&ctx->rm->lock);

    Route active;
    int idx = routemanager_get_active(ctx->rm, &active);
    if (idx < 0) return; /* no working route - drop, client will just see a timeout like normal */

    unsigned char fallback[4096];
    int fallback_len = 0;
    int have_fallback = 0;

    for (int i = 0; i < cfg->dns_upstream_count; i++) {
        SOCKET tcp = connect_via_route(&active, cfg->dns_upstream_host[i], cfg->dns_upstream_port[i]);
        if (tcp == INVALID_SOCKET) continue;

        unsigned char lenprefix[2];
        lenprefix[0] = (unsigned char)((ctx->query_len >> 8) & 0xFF);
        lenprefix[1] = (unsigned char)(ctx->query_len & 0xFF);

        if (!send_all(tcp, (char*)lenprefix, 2) || !send_all(tcp, (char*)ctx->query, ctx->query_len)) {
            closesocket(tcp);
            continue;
        }

        unsigned char resplen_b[2];
        if (recv_exact(tcp, (char*)resplen_b, 2, 5000) < 0) { closesocket(tcp); continue; }
        int resplen = (resplen_b[0] << 8) | resplen_b[1];
        if (resplen <= 0 || resplen > 4096) { closesocket(tcp); continue; }

        unsigned char respbuf[4096];
        if (recv_exact(tcp, (char*)respbuf, resplen, 5000) < 0) { closesocket(tcp); continue; }
        closesocket(tcp);

        if (!have_fallback) {
            memcpy(fallback, respbuf, resplen);
            fallback_len = resplen;
            have_fallback = 1;
        }

        int rcode = (resplen >= 4) ? (respbuf[3] & 0x0F) : -1;
        if (rcode == 0) {
            sendto(ctx->udp_sock, (char*)respbuf, resplen, 0,
                   (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);
            return;
        }
        /* NXDOMAIN / SERVFAIL / REFUSED / etc - this resolver doesn't have
           it, try the next configured upstream */
    }

    if (have_fallback) {
        sendto(ctx->udp_sock, (char*)fallback, fallback_len, 0,
               (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);
    }
    /* otherwise not even one upstream was reachable at the transport level -
       drop, same as a normal DNS timeout */
}

static DWORD WINAPI dns_query_thread(LPVOID param) {
    DnsQueryCtx *ctx = (DnsQueryCtx*)param;
    handle_dns_query(ctx);
    free(ctx);
    return 0;
}

#define DNS_STATE_OFF 0
#define DNS_STATE_UP 1
#define DNS_STATE_FAILED 2

static SOCKET try_bind_dns_udp(const char *bind_addr, int port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        return s;
    }
    closesocket(s);
    return INVALID_SOCKET;
}

DWORD WINAPI dns_server_thread(LPVOID param) {
    RouteManager *rm = (RouteManager*)param;
    SOCKET udp_sock = INVALID_SOCKET;
    char configured_bind[MAX_HOST_LEN] = ""; /* what the .ini last asked for */
    int configured_port = 0;
    char actual_bind[MAX_HOST_LEN] = "";     /* what we actually ended up bound to */
    int state = DNS_STATE_OFF;
    int retry_countdown = 0;

    while (rm->running) {
        Config *cfg;
        EnterCriticalSection(&rm->lock);
        cfg = rm->cfg;
        LeaveCriticalSection(&rm->lock);

        int want_enabled = cfg->dns_enabled;
        int config_changed = (state != DNS_STATE_OFF) &&
            (strcmp(cfg->dns_bind, configured_bind) != 0 || cfg->dns_port != configured_port);

        if (!want_enabled) {
            if (state != DNS_STATE_OFF) {
                if (udp_sock != INVALID_SOCKET) { closesocket(udp_sock); udp_sock = INVALID_SOCKET; }
                log_msg("DNS: local DNS server turned off by config");
                state = DNS_STATE_OFF;
            }
        } else if (state == DNS_STATE_OFF || config_changed ||
                   (state == DNS_STATE_FAILED && retry_countdown <= 0)) {
            if (udp_sock != INVALID_SOCKET) { closesocket(udp_sock); udp_sock = INVALID_SOCKET; }

            snprintf(configured_bind, sizeof(configured_bind), "%s", cfg->dns_bind);
            configured_port = cfg->dns_port;

            SOCKET s = try_bind_dns_udp(cfg->dns_bind, cfg->dns_port);
            int used_fallback = 0;

            /* "Sticky" DNS: if 0.0.0.0 (every interface) is taken by
               something else, try just the loopback interface instead -
               this machine can still use its own DNS relay even though
               other devices on the network can no longer reach it here. */
            if (s == INVALID_SOCKET && strcmp(cfg->dns_bind, "0.0.0.0") == 0) {
                s = try_bind_dns_udp("127.0.0.1", cfg->dns_port);
                if (s != INVALID_SOCKET) used_fallback = 1;
            }

            if (s != INVALID_SOCKET) {
                udp_sock = s;
                snprintf(actual_bind, sizeof(actual_bind), "%s", used_fallback ? "127.0.0.1" : cfg->dns_bind);
                if (used_fallback) {
                    log_msg("DNS: %s:%d was unavailable - stuck to 127.0.0.1:%d instead "
                            "(this machine only; something else already holds the port on other interfaces)",
                            cfg->dns_bind, cfg->dns_port, cfg->dns_port);
                }
                log_msg("DNS: listening on UDP %s:%d, %d upstream resolver(s) configured, forwarding through the active route",
                        actual_bind, cfg->dns_port, cfg->dns_upstream_count);
                state = DNS_STATE_UP;
            } else {
                if (state != DNS_STATE_FAILED) {
                    log_msg("DNS: could not bind UDP %s:%d (already in use by another DNS server?) "
                            "- local DNS stays off, the rest of the proxy is unaffected. "
                            "Will keep retrying quietly in case the port frees up.",
                            cfg->dns_bind, cfg->dns_port);
                }
                state = DNS_STATE_FAILED;
                retry_countdown = 30;
            }
        }

        if (state != DNS_STATE_UP) {
            if (retry_countdown > 0) retry_countdown--;
            Sleep(1000);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(udp_sock, &rfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        DnsQueryCtx *ctx = (DnsQueryCtx*)malloc(sizeof(DnsQueryCtx));
        if (!ctx) continue;

        int fromlen = sizeof(ctx->client_addr);
        int n = recvfrom(udp_sock, (char*)ctx->query, sizeof(ctx->query), 0,
                          (struct sockaddr*)&ctx->client_addr, &fromlen);
        if (n <= 0) { free(ctx); continue; }

        ctx->query_len = n;
        ctx->client_addr_len = fromlen;
        ctx->rm = rm;
        ctx->udp_sock = udp_sock;

        HANDLE h = CreateThread(NULL, 0, dns_query_thread, ctx, 0, NULL);
        if (h) CloseHandle(h);
    }

    if (udp_sock != INVALID_SOCKET) closesocket(udp_sock);
    return 0;
}
