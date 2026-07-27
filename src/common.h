#ifndef COMMON_H
#define COMMON_H

/* Explicitly target Windows Vista as the API floor. This both unlocks
   Vista-era functions we want (inet_pton/inet_ntop appeared in Vista)
   and acts as a compile-time tripwire: if we accidentally reference
   something newer, headers will refuse to declare it. */
#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>

#define PROXY_VERSION "0.5"
#define SERVICE_DEFAULT_NAME "Dynamic proxy"
#define SERVICE_DEFAULT_DESCRIPTION "Extended Dynamic proxy"

#define MAX_ROUTES 16
#define MAX_HOST_LEN 256
#define MAX_CRED_LEN 128
#define RECV_BUF_SIZE 16384
#define MAX_DNS_UPSTREAMS 16

typedef enum {
    ROUTE_DIRECT = 0,
    ROUTE_SOCKS5 = 1,
    ROUTE_HTTP = 2
} RouteType;

typedef struct {
    RouteType type;
    char host[MAX_HOST_LEN];
    int port;
    char username[MAX_CRED_LEN];
    char password[MAX_CRED_LEN];
    int has_auth;
} Route;

typedef struct {
    char listen_bind[MAX_HOST_LEN];
    int listen_port;

    Route routes[MAX_ROUTES];
    int route_count;

    int health_interval_sec;
    int health_fail_threshold;
    char check_host[MAX_HOST_LEN]; /* empty = use built-in defaults */
    int check_port;

    int dns_enabled;
    char dns_bind[MAX_HOST_LEN];
    int dns_port;
    char dns_upstream_host[MAX_DNS_UPSTREAMS][MAX_HOST_LEN];
    int dns_upstream_port[MAX_DNS_UPSTREAMS];
    int dns_upstream_count;

    char log_path[512]; /* empty = console only (this is the default) */
} Config;

/* Values the user pinned on the command line - these win over whatever
   is in the .ini, on every load AND on every hot-reload. */
typedef struct {
    int port_set;             int port;
    int bind_set;              char bind[MAX_HOST_LEN];
    int log_set;                char log_path[512];
    int health_interval_set;   int health_interval;
} CliOverrides;

typedef enum { SVC_ACTION_RUN = 0, SVC_ACTION_INSTALL, SVC_ACTION_UNINSTALL } ServiceAction;

typedef struct {
    ServiceAction action;
    int is_service;                 /* --service: being launched by the SCM right now */
    char name[256];                 /* --name, default "Dynamic proxy" */
    char description[512];          /* --description, install-time only */
} ServiceArgs;

/* --- config.c --- */
int config_load(const char *path, Config *cfg);
void config_defaults(Config *cfg);
void parse_cli(int argc, char **argv, char *config_path_out, int config_path_sz, CliOverrides *ov);
void apply_cli_overrides(Config *cfg, const CliOverrides *ov);
/* Full path to the running exe with its extension swapped for .ini,
   e.g. C:\tools\myproxy.exe -> C:\tools\myproxy.ini */
int get_module_ini_path(char *out, int outsz);

/* --- log.c --- */
void log_init(const char *path);
void log_msg(const char *fmt, ...);

/* --- netutil.c / upstream.c --- */
SOCKET connect_tcp_raw(const char *host, int port);
int send_all(SOCKET s, const char *buf, int len);
int recv_some(SOCKET s, char *buf, int buflen, int timeout_ms);
/* Loops internally until exactly n bytes arrive (TCP may deliver a
   handshake in several small chunks) or fails/times out. */
int recv_exact(SOCKET s, char *buf, int n, int timeout_ms);

/* Establish an end-to-end tunnel to (target_host,target_port) via the given route.
   target_host may be a domain name (preferred for socks5/http routes: resolution
   happens on the upstream side, not locally) or an IPv4 literal. */
SOCKET connect_via_route(const Route *route, const char *target_host, int target_port);

/* --- healthcheck.c --- */
typedef struct {
    Config *cfg;                 /* swapped wholesale on hot-reload; old ones are
                                     intentionally never freed (tiny struct, and
                                     in-flight connections keep their own Route copy) */
    CRITICAL_SECTION lock;
    int active_index;            /* -2 = not checked yet, -1 = checked, none work, >=0 = index into cfg->routes */
    volatile int running;

    char config_path[512];
    time_t config_mtime;
    CliOverrides overrides;

    int listen_generation;       /* bumped whenever [listen] changes, so main's accept loop knows to rebind */
} RouteManager;

void routemanager_init(RouteManager *rm, Config *cfg, const char *config_path, const CliOverrides *overrides);
DWORD WINAPI routemanager_thread(LPVOID param);
int routemanager_get_active(RouteManager *rm, Route *out_route /* copy */);
int check_route_alive(const Route *route, const Config *cfg);

/* --- listeners.c --- */
typedef struct {
    SOCKET client_sock;
    RouteManager *rm;
} ClientCtx;

DWORD WINAPI handle_client_thread(LPVOID param);
void relay_loop(SOCKET a, SOCKET b);

/* --- dns.c --- */
DWORD WINAPI dns_server_thread(LPVOID param);

/* --- main.c --- */
SOCKET create_and_bind_listen_socket(const Config *cfg);
int run_proxy(const char *config_path, const CliOverrides *overrides);

/* --- service.c --- */
void parse_service_args(int argc, char **argv, ServiceArgs *sa);
int install_service(const ServiceArgs *sa, const char *config_path, int cp_was_explicit);
int uninstall_service(const ServiceArgs *sa);
void service_set_context(const char *config_path, const CliOverrides *overrides, const char *service_name);
int run_as_service(const char *service_name);
/* Asks the SCM which service name corresponds to the currently running
   process (matched by PID) - lets a service discover its own name at
   runtime instead of needing --name baked into its command line. */
int discover_own_service_name(char *out, int outsz);

#endif
