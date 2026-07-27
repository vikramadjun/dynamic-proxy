#include "common.h"

void relay_loop(SOCKET a, SOCKET b) {
    char buf[RECV_BUF_SIZE];
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);

        int rc = select(0, &rfds, NULL, NULL, NULL);
        if (rc <= 0) break;

        if (FD_ISSET(a, &rfds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (!send_all(b, buf, n)) break;
        }
        if (FD_ISSET(b, &rfds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (!send_all(a, buf, n)) break;
        }
    }
}

/* ---------------- SOCKS5 listener side ---------------- */

static void run_socks5_client(SOCKET client, RouteManager *rm) {
    unsigned char greet[2];
    if (recv_exact(client, (char*)greet, 2, 10000) < 0) return;
    if (greet[0] != 0x05) return;

    int nmethods = greet[1];
    unsigned char methods[255];
    if (nmethods > 0 && recv_exact(client, (char*)methods, nmethods, 5000) < 0) return;

    unsigned char choice[2] = {0x05, 0x00};
    if (!send_all(client, (char*)choice, 2)) return;

    unsigned char req_head[4];
    if (recv_exact(client, (char*)req_head, 4, 10000) < 0) return;

    if (req_head[0] != 0x05 || req_head[1] != 0x01) {
        unsigned char fail[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0};
        send_all(client, (char*)fail, 10);
        return;
    }

    char target_host[MAX_HOST_LEN];
    int target_port;

    switch (req_head[3]) {
        case 0x01: {
            unsigned char addr[4];
            if (recv_exact(client, (char*)addr, 4, 5000) < 0) return;
            snprintf(target_host, sizeof(target_host), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
            break;
        }
        case 0x03: {
            unsigned char l;
            if (recv_exact(client, (char*)&l, 1, 5000) < 0) return;
            if (recv_exact(client, target_host, l, 5000) < 0) return;
            target_host[l] = 0;
            break;
        }
        case 0x04: {
            unsigned char fail[10] = {0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0};
            send_all(client, (char*)fail, 10);
            return;
        }
        default:
            return;
    }

    unsigned char portb[2];
    if (recv_exact(client, (char*)portb, 2, 5000) < 0) return;
    target_port = (portb[0] << 8) | portb[1];

    Route active;
    int idx = routemanager_get_active(rm, &active);
    if (idx < 0) {
        log_msg("Refusing client (SOCKS5): no working route (request to %s:%d)", target_host, target_port);
        unsigned char fail[10] = {0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0};
        send_all(client, (char*)fail, 10);
        return;
    }

    SOCKET upstream = connect_via_route(&active, target_host, target_port);
    if (upstream == INVALID_SOCKET) {
        log_msg("Failed to connect to %s:%d via route%d (SOCKS5)", target_host, target_port, idx + 1);
        unsigned char fail[10] = {0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0};
        send_all(client, (char*)fail, 10);
        return;
    }

    unsigned char ok[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    if (!send_all(client, (char*)ok, 10)) { closesocket(upstream); return; }

    log_msg("SOCKS5: %s:%d via route%d", target_host, target_port, idx + 1);
    relay_loop(client, upstream);
    closesocket(upstream);
}

/* ---------------- HTTP(S) listener side ---------------- */

static int read_headers(SOCKET client, char *buf, int bufcap, int *out_total, int *out_header_len) {
    int total = 0;
    for (;;) {
        int n = recv_some(client, buf + total, bufcap - 1 - total, 15000);
        if (n <= 0) return 0;
        total += n;
        buf[total] = 0;
        char *p = strstr(buf, "\r\n\r\n");
        if (p) {
            *out_total = total;
            *out_header_len = (int)(p - buf);
            return 1;
        }
        if (total >= bufcap - 1) return 0; /* headers too large, refuse rather than mis-parse */
    }
}

/* Parses "http://host[:port]/path..." (or bare "host[:port]/path").
   *path_out points inside `target` itself, valid as long as target lives. */
static int parse_target_url(const char *target, char *host_out, int host_out_sz, int *port_out, const char **path_out) {
    const char *p = target;
    if (_strnicmp(p, "http://", 7) == 0) p += 7;
    else if (_strnicmp(p, "https://", 8) == 0) p += 8;

    const char *slash = strchr(p, '/');
    int hplen = slash ? (int)(slash - p) : (int)strlen(p);
    char hostport[300];
    if (hplen <= 0 || hplen >= (int)sizeof(hostport)) return 0;
    memcpy(hostport, p, hplen);
    hostport[hplen] = 0;

    char *colon = strchr(hostport, ':');
    if (colon) {
        *colon = 0;
        snprintf(host_out, host_out_sz, "%s", hostport);
        *port_out = atoi(colon + 1);
    } else {
        snprintf(host_out, host_out_sz, "%s", hostport);
        *port_out = 80;
    }
    *path_out = slash ? slash : "/";
    return 1;
}

static void run_http_client(SOCKET client, RouteManager *rm) {
    char buf[8192];
    int total = 0, header_len = 0;
    if (!read_headers(client, buf, sizeof(buf), &total, &header_len)) return;

    int body_start_offset = header_len + 4;
    int leftover_len = total - body_start_offset;

    char *line_end = strstr(buf, "\r\n");
    if (!line_end || line_end > buf + header_len) return;
    int line_len = (int)(line_end - buf);
    if (line_len >= 2048) return;
    char request_line[2048];
    memcpy(request_line, buf, line_len);
    request_line[line_len] = 0;

    char method[16], target[2048], httpver[16];
    if (sscanf(request_line, "%15s %2047s %15s", method, target, httpver) != 3) return;

    char target_host[MAX_HOST_LEN];
    int target_port;
    int is_connect = (_stricmp(method, "CONNECT") == 0);
    const char *path = "/";

    if (is_connect) {
        char t[300];
        strncpy(t, target, sizeof(t) - 1); t[sizeof(t) - 1] = 0;
        char *colon = strrchr(t, ':');
        if (!colon) return;
        *colon = 0;
        strncpy(target_host, t, sizeof(target_host) - 1);
        target_host[sizeof(target_host) - 1] = 0;
        target_port = atoi(colon + 1);
    } else {
        if (!parse_target_url(target, target_host, sizeof(target_host), &target_port, &path)) return;
    }

    Route active;
    int idx = routemanager_get_active(rm, &active);
    if (idx < 0) {
        log_msg("Refusing client (HTTP): no working route (request to %s:%d)", target_host, target_port);
        send_all(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n", 29);
        return;
    }

    SOCKET upstream = connect_via_route(&active, target_host, target_port);
    if (upstream == INVALID_SOCKET) {
        log_msg("Failed to connect to %s:%d via route%d (HTTP)", target_host, target_port, idx + 1);
        send_all(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n", 29);
        return;
    }

    if (is_connect) {
        if (!send_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n", 40)) { closesocket(upstream); return; }
        log_msg("HTTP CONNECT: %s:%d via route%d", target_host, target_port, idx + 1);
    } else {
        char outbuf[8192];
        int outlen = 0;
        outlen += snprintf(outbuf + outlen, sizeof(outbuf) - outlen, "%s %s %s\r\n", method, path, httpver);

        char *cursor = line_end + 2;
        while (cursor < buf + header_len) {
            char *next = strstr(cursor, "\r\n");
            if (!next || next > buf + header_len) next = buf + header_len;
            int llen = (int)(next - cursor);
            if (llen > 0 && llen < 1024 && outlen < (int)sizeof(outbuf) - 1100) {
                char hline[1024];
                memcpy(hline, cursor, llen);
                hline[llen] = 0;
                if (_strnicmp(hline, "Proxy-", 6) != 0) {
                    outlen += snprintf(outbuf + outlen, sizeof(outbuf) - outlen, "%s\r\n", hline);
                }
            }
            cursor = next + 2;
        }
        if (outlen < (int)sizeof(outbuf) - 4) {
            outlen += snprintf(outbuf + outlen, sizeof(outbuf) - outlen, "\r\n");
        }

        if (!send_all(upstream, outbuf, outlen)) { closesocket(upstream); return; }
        if (leftover_len > 0) {
            if (!send_all(upstream, buf + body_start_offset, leftover_len)) { closesocket(upstream); return; }
        }
        log_msg("HTTP %s: %s:%d via route%d", method, target_host, target_port, idx + 1);
    }

    relay_loop(client, upstream);
    closesocket(upstream);
}

/* ---------------- shared entry point ---------------- */

DWORD WINAPI handle_client_thread(LPVOID param) {
    ClientCtx *ctx = (ClientCtx*)param;
    SOCKET client = ctx->client_sock;
    RouteManager *rm = ctx->rm;
    free(ctx);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(client, &rfds);
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    int sel = select(0, &rfds, NULL, NULL, &tv);
    if (sel <= 0) { closesocket(client); return 0; }

    unsigned char peek_byte = 0;
    int pn = recv(client, (char*)&peek_byte, 1, MSG_PEEK);
    if (pn <= 0) { closesocket(client); return 0; }

    if (peek_byte == 0x05) {
        run_socks5_client(client, rm);
    } else {
        run_http_client(client, rm);
    }

    closesocket(client);
    return 0;
}
