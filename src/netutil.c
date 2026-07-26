#include "common.h"

SOCKET connect_tcp_raw(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return INVALID_SOCKET;
    }

    SOCKET s = INVALID_SOCKET;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        int rc = connect(s, rp->ai_addr, (int)rp->ai_addrlen);
        int connected = 0;
        int lasterr = 0;

        if (rc == 0) {
            connected = 1;
        } else {
            lasterr = WSAGetLastError();
            if (lasterr == WSAEWOULDBLOCK) {
                fd_set wfds, efds;
                FD_ZERO(&wfds);
                FD_ZERO(&efds);
                FD_SET(s, &wfds);
                FD_SET(s, &efds);
                struct timeval tv;
                tv.tv_sec = 5;
                tv.tv_usec = 0;
                int sel = select(0, NULL, &wfds, &efds, &tv);
                if (sel > 0 && (FD_ISSET(s, &wfds) || FD_ISSET(s, &efds))) {
                    int soerr = 0;
                    int soerrlen = sizeof(soerr);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &soerrlen);
                    if (soerr == 0) {
                        connected = 1;
                    } else {
                        lasterr = soerr;
                    }
                } else if (sel == 0) {
                    lasterr = WSAETIMEDOUT;
                } else {
                    lasterr = WSAGetLastError();
                }
            }
        }

        if (connected) {
            mode = 0;
            ioctlsocket(s, FIONBIO, &mode);
            break;
        }

        (void)lasterr;
        closesocket(s);
        s = INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return s;
}

int send_all(SOCKET s, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int rc = send(s, buf + sent, len - sent, 0);
        if (rc == SOCKET_ERROR || rc == 0) return 0;
        sent += rc;
    }
    return 1;
}

int recv_some(SOCKET s, char *buf, int buflen, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(0, &rfds, NULL, NULL, &tv);
    if (sel <= 0) return -1;

    int rc = recv(s, buf, buflen, 0);
    if (rc == SOCKET_ERROR) return -1;
    return rc; /* 0 = peer closed, >0 = bytes */
}

int recv_exact(SOCKET s, char *buf, int n, int timeout_ms) {
    int got = 0;
    while (got < n) {
        int rc = recv_some(s, buf + got, n - got, timeout_ms);
        if (rc <= 0) return -1;
        got += rc;
    }
    return got;
}
