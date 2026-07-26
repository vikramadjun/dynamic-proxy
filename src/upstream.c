#include "common.h"

static void base64_encode(const char *in, int inlen, char *out) {
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int oi = 0, ii = 0;
    while (ii + 3 <= inlen) {
        unsigned int n = ((unsigned char)in[ii] << 16) | ((unsigned char)in[ii+1] << 8) | (unsigned char)in[ii+2];
        out[oi++] = tab[(n >> 18) & 63];
        out[oi++] = tab[(n >> 12) & 63];
        out[oi++] = tab[(n >> 6) & 63];
        out[oi++] = tab[n & 63];
        ii += 3;
    }
    int rem = inlen - ii;
    if (rem == 1) {
        unsigned int n = (unsigned char)in[ii] << 16;
        out[oi++] = tab[(n >> 18) & 63];
        out[oi++] = tab[(n >> 12) & 63];
        out[oi++] = '=';
        out[oi++] = '=';
    } else if (rem == 2) {
        unsigned int n = ((unsigned char)in[ii] << 16) | ((unsigned char)in[ii+1] << 8);
        out[oi++] = tab[(n >> 18) & 63];
        out[oi++] = tab[(n >> 12) & 63];
        out[oi++] = tab[(n >> 6) & 63];
        out[oi++] = '=';
    }
    out[oi] = 0;
}

static SOCKET socks5_upstream_connect(const Route *route, const char *target_host, int target_port) {
    SOCKET s = connect_tcp_raw(route->host, route->port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    unsigned char greeting[4];
    int idx = 0;
    greeting[idx++] = 0x05;
    if (route->has_auth) {
        greeting[idx++] = 2;
        greeting[idx++] = 0x00;
        greeting[idx++] = 0x02;
    } else {
        greeting[idx++] = 1;
        greeting[idx++] = 0x00;
    }
    if (!send_all(s, (char*)greeting, idx)) { closesocket(s); return INVALID_SOCKET; }

    unsigned char resp[2];
    if (recv_exact(s, (char*)resp, 2, 5000) < 0) { closesocket(s); return INVALID_SOCKET; }
    if (resp[0] != 0x05) { closesocket(s); return INVALID_SOCKET; }

    if (resp[1] == 0x02) {
        char authbuf[512];
        int alen = 0;
        authbuf[alen++] = 0x01;
        int ulen = (int)strlen(route->username);
        authbuf[alen++] = (unsigned char)ulen;
        memcpy(authbuf + alen, route->username, ulen); alen += ulen;
        int plen = (int)strlen(route->password);
        authbuf[alen++] = (unsigned char)plen;
        memcpy(authbuf + alen, route->password, plen); alen += plen;

        if (!send_all(s, authbuf, alen)) { closesocket(s); return INVALID_SOCKET; }
        unsigned char authresp[2];
        if (recv_exact(s, (char*)authresp, 2, 5000) < 0 || authresp[1] != 0x00) {
            closesocket(s); return INVALID_SOCKET;
        }
    } else if (resp[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    char req[300];
    int rlen = 0;
    req[rlen++] = 0x05;
    req[rlen++] = 0x01;
    req[rlen++] = 0x00;
    req[rlen++] = 0x03; /* domain name ATYP: let the upstream resolve it */
    int hlen = (int)strlen(target_host);
    if (hlen > 255) hlen = 255;
    req[rlen++] = (unsigned char)hlen;
    memcpy(req + rlen, target_host, hlen); rlen += hlen;
    req[rlen++] = (unsigned char)((target_port >> 8) & 0xFF);
    req[rlen++] = (unsigned char)(target_port & 0xFF);

    if (!send_all(s, req, rlen)) { closesocket(s); return INVALID_SOCKET; }

    unsigned char head[4];
    if (recv_exact(s, (char*)head, 4, 5000) < 0) { closesocket(s); return INVALID_SOCKET; }
    if (head[0] != 0x05 || head[1] != 0x00) { closesocket(s); return INVALID_SOCKET; }

    int addr_len;
    switch (head[3]) {
        case 0x01: addr_len = 4; break;
        case 0x04: addr_len = 16; break;
        case 0x03: {
            unsigned char l;
            if (recv_exact(s, (char*)&l, 1, 5000) < 0) { closesocket(s); return INVALID_SOCKET; }
            addr_len = l;
            break;
        }
        default: closesocket(s); return INVALID_SOCKET;
    }
    char discard[260];
    if (recv_exact(s, discard, addr_len + 2, 5000) < 0) { closesocket(s); return INVALID_SOCKET; }

    return s;
}

static SOCKET http_upstream_connect(const Route *route, const char *target_host, int target_port) {
    SOCKET s = connect_tcp_raw(route->host, route->port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    char req[1024];
    int len;

    if (route->has_auth) {
        char credraw[256];
        snprintf(credraw, sizeof(credraw), "%s:%s", route->username, route->password);
        char b64out[400];
        base64_encode(credraw, (int)strlen(credraw), b64out);

        len = snprintf(req, sizeof(req),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
            target_host, target_port, target_host, target_port, b64out);
    } else {
        len = snprintf(req, sizeof(req),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
            target_host, target_port, target_host, target_port);
    }

    if (!send_all(s, req, len)) { closesocket(s); return INVALID_SOCKET; }

    char resp[4096];
    int total = 0;
    for (;;) {
        int n = recv_some(s, resp + total, sizeof(resp) - 1 - total, 5000);
        if (n <= 0) { closesocket(s); return INVALID_SOCKET; }
        total += n;
        resp[total] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
        if (total >= (int)sizeof(resp) - 1) { closesocket(s); return INVALID_SOCKET; }
    }

    if (strncmp(resp, "HTTP/1.", 7) != 0) { closesocket(s); return INVALID_SOCKET; }
    char *sp = strchr(resp, ' ');
    if (!sp || atoi(sp + 1) != 200) { closesocket(s); return INVALID_SOCKET; }

    return s;
}

SOCKET connect_via_route(const Route *route, const char *target_host, int target_port) {
    switch (route->type) {
        case ROUTE_DIRECT:
            return connect_tcp_raw(target_host, target_port);
        case ROUTE_SOCKS5:
            return socks5_upstream_connect(route, target_host, target_port);
        case ROUTE_HTTP:
            return http_upstream_connect(route, target_host, target_port);
    }
    return INVALID_SOCKET;
}
