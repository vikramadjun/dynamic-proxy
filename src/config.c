#include "common.h"

void config_defaults(Config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->listen_bind, "127.0.0.1", MAX_HOST_LEN - 1);
    cfg->listen_port = 1080;
    cfg->route_count = 0;
    cfg->health_interval_sec = 10;
    cfg->health_fail_threshold = 2;

    cfg->dns_enabled = 0;
    strncpy(cfg->dns_bind, "127.0.0.1", MAX_HOST_LEN - 1);
    cfg->dns_port = 53;
    cfg->dns_upstream_count = 0; /* filled from ini, or defaulted at the end of config_load */

    cfg->log_path[0] = 0; /* console-only unless -l/--log or [log] path= says otherwise */
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = 0;
        end--;
    }
    return s;
}

static RouteType parse_route_type(const char *s) {
    if (_stricmp(s, "socks5") == 0) return ROUTE_SOCKS5;
    if (_stricmp(s, "http") == 0 || _stricmp(s, "https") == 0) return ROUTE_HTTP;
    return ROUTE_DIRECT;
}

static int parse_bool(const char *s) {
    return (_stricmp(s, "yes") == 0 || _stricmp(s, "true") == 0 || _stricmp(s, "1") == 0 || _stricmp(s, "on") == 0);
}

static void parse_host_port(const char *val, char *host_out, int host_out_sz, int *port_out) {
    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%s", val);
    char *colon = strrchr(tmp, ':');
    if (colon) {
        *colon = 0;
        snprintf(host_out, host_out_sz, "%s", tmp);
        *port_out = atoi(colon + 1);
    } else {
        snprintf(host_out, host_out_sz, "%s", tmp);
    }
}

/* Pulls DNS servers configured on every UP, non-loopback network adapter
   (manual or DHCP-assigned - Windows doesn't distinguish them here) into
   the given arrays, up to max_out entries. Used for "upstream = NC". */
static int gather_nic_dns_servers(char hosts[][MAX_HOST_LEN], int ports[], int max_out) {
    ULONG bufsize = 16384;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    int ok = 0;

    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        addrs = (IP_ADAPTER_ADDRESSES*)malloc(bufsize);
        if (!addrs) return 0;
        ULONG rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                        NULL, addrs, &bufsize);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free(addrs);
            addrs = NULL;
            continue;
        }
        if (rc != NO_ERROR) {
            free(addrs);
            return 0;
        }
        ok = 1;
    }
    if (!ok || !addrs) return 0;

    int count = 0;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a && count < max_out; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = a->FirstDnsServerAddress; d && count < max_out; d = d->Next) {
            struct sockaddr_in *sin = (struct sockaddr_in*)d->Address.lpSockaddr;
            if (!sin || sin->sin_family != AF_INET) continue;
            char ipbuf[64];
            if (!inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf))) continue;
            snprintf(hosts[count], MAX_HOST_LEN, "%s", ipbuf);
            ports[count] = 53;
            count++;
        }
    }

    free(addrs);
    return count;
}

static void add_dns_upstream(Config *cfg, const char *value) {
    if (_stricmp(value, "NC") == 0) {
        int room = MAX_DNS_UPSTREAMS - cfg->dns_upstream_count;
        if (room <= 0) return;
        int added = gather_nic_dns_servers(cfg->dns_upstream_host + cfg->dns_upstream_count,
                                            cfg->dns_upstream_port + cfg->dns_upstream_count,
                                            room);
        if (added == 0) {
            log_msg("DNS: \"NC\" found no DNS servers on any active network adapter");
        } else {
            log_msg("DNS: \"NC\" picked up %d server(s) from active network adapters", added);
        }
        cfg->dns_upstream_count += added;
        return;
    }

    if (cfg->dns_upstream_count >= MAX_DNS_UPSTREAMS) {
        log_msg("Warning: exceeded max number of DNS upstreams (%d), ignoring extra entries", MAX_DNS_UPSTREAMS);
        return;
    }
    parse_host_port(value, cfg->dns_upstream_host[cfg->dns_upstream_count],
                    MAX_HOST_LEN, &cfg->dns_upstream_port[cfg->dns_upstream_count]);
    cfg->dns_upstream_count++;
}

/* Drops any upstream entry that points straight back at our own DNS
   listener (127.0.0.1 on the same port we ourselves listen on) - otherwise
   a query would just loop back to us instead of ever getting answered.
   This can happen innocently: e.g. the network adapter's DNS is set to
   127.0.0.1 (pointing at this proxy) and "upstream = NC" then picks that
   same address back up from the adapter. */
static void remove_self_referencing_dns_upstreams(Config *cfg) {
    int write = 0;
    for (int read = 0; read < cfg->dns_upstream_count; read++) {
        int is_self = (cfg->dns_upstream_port[read] == cfg->dns_port) &&
                      _stricmp(cfg->dns_upstream_host[read], "127.0.0.1") == 0;
        if (is_self) {
            log_msg("DNS: upstream %s:%d points back at this proxy's own DNS server - skipping it "
                    "(a query sent there would just loop back to us and never get answered)",
                    cfg->dns_upstream_host[read], cfg->dns_upstream_port[read]);
            continue;
        }
        if (write != read) {
            snprintf(cfg->dns_upstream_host[write], MAX_HOST_LEN, "%s", cfg->dns_upstream_host[read]);
            cfg->dns_upstream_port[write] = cfg->dns_upstream_port[read];
        }
        write++;
    }
    cfg->dns_upstream_count = write;
}

int config_load(const char *path, Config *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg("Could not open config file: %s", path);
        return 0;
    }

    char line[1024];
    char section[64] = "";
    Route *cur_route = NULL;
    cfg->route_count = 0;        /* reload starts the route list fresh */
    cfg->dns_upstream_count = 0; /* same for the DNS upstream list */

    while (fgets(line, sizeof(line), f)) {
        char *l = trim(line);
        if (l[0] == 0 || l[0] == ';' || l[0] == '#') continue;

        if (l[0] == '[') {
            char *close = strchr(l, ']');
            if (close) {
                *close = 0;
                strncpy(section, l + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = 0;

                if (_strnicmp(section, "route", 5) == 0) {
                    if (cfg->route_count < MAX_ROUTES) {
                        cur_route = &cfg->routes[cfg->route_count];
                        memset(cur_route, 0, sizeof(*cur_route));
                        cur_route->type = ROUTE_DIRECT;
                        cur_route->port = 0;
                        cfg->route_count++;
                    } else {
                        log_msg("Warning: exceeded max number of routes (%d), extra sections ignored", MAX_ROUTES);
                        cur_route = NULL;
                    }
                } else {
                    cur_route = NULL;
                }
            }
            continue;
        }

        char *eq = strchr(l, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = trim(l);
        char *val = trim(eq + 1);

        if (_stricmp(section, "listen") == 0) {
            if (_stricmp(key, "port") == 0) cfg->listen_port = atoi(val);
            else if (_stricmp(key, "bind") == 0) strncpy(cfg->listen_bind, val, MAX_HOST_LEN - 1);
        } else if (_stricmp(section, "health") == 0) {
            if (_stricmp(key, "interval_sec") == 0) cfg->health_interval_sec = atoi(val);
            else if (_stricmp(key, "fail_threshold") == 0) cfg->health_fail_threshold = atoi(val);
            else if (_stricmp(key, "check_host") == 0) strncpy(cfg->check_host, val, MAX_HOST_LEN - 1);
            else if (_stricmp(key, "check_port") == 0) cfg->check_port = atoi(val);
        } else if (_stricmp(section, "dns") == 0) {
            if (_stricmp(key, "enabled") == 0) cfg->dns_enabled = parse_bool(val);
            else if (_stricmp(key, "bind") == 0) strncpy(cfg->dns_bind, val, MAX_HOST_LEN - 1);
            else if (_stricmp(key, "port") == 0) cfg->dns_port = atoi(val);
            else if (_stricmp(key, "upstream") == 0) add_dns_upstream(cfg, val);
        } else if (_stricmp(section, "log") == 0) {
            if (_stricmp(key, "path") == 0) strncpy(cfg->log_path, val, sizeof(cfg->log_path) - 1);
        } else if (_strnicmp(section, "route", 5) == 0 && cur_route) {
            if (_stricmp(key, "type") == 0) cur_route->type = parse_route_type(val);
            else if (_stricmp(key, "host") == 0) strncpy(cur_route->host, val, MAX_HOST_LEN - 1);
            else if (_stricmp(key, "port") == 0) cur_route->port = atoi(val);
            else if (_stricmp(key, "username") == 0) {
                strncpy(cur_route->username, val, MAX_CRED_LEN - 1);
                if (val[0]) cur_route->has_auth = 1;
            } else if (_stricmp(key, "password") == 0) {
                strncpy(cur_route->password, val, MAX_CRED_LEN - 1);
            }
        }
    }

    fclose(f);

    if (cfg->route_count == 0) {
        log_msg("No [routeN] sections found in config - adding direct connection by default");
        cfg->routes[0].type = ROUTE_DIRECT;
        cfg->route_count = 1;
    }

    remove_self_referencing_dns_upstreams(cfg);

    if (cfg->dns_upstream_count == 0) {
        snprintf(cfg->dns_upstream_host[0], MAX_HOST_LEN, "1.1.1.1");
        cfg->dns_upstream_port[0] = 53;
        cfg->dns_upstream_count = 1;
    }

    return 1;
}

int get_module_ini_path(char *out, int outsz) {
    char modpath[480];
    DWORD n = GetModuleFileNameA(NULL, modpath, sizeof(modpath));
    if (n == 0 || n >= sizeof(modpath)) return 0;

    char *dot = strrchr(modpath, '.');
    char *slash1 = strrchr(modpath, '\\');
    char *slash2 = strrchr(modpath, '/');
    char *lastslash = slash1 > slash2 ? slash1 : slash2;

    if (!dot || (lastslash && dot < lastslash)) {
        snprintf(out, outsz, "%s.ini", modpath);
        return 1;
    }
    int prefixlen = (int)(dot - modpath);
    if (prefixlen >= outsz) return 0;
    memcpy(out, modpath, prefixlen);
    snprintf(out + prefixlen, outsz - prefixlen, ".ini");
    return 1;
}

void parse_cli(int argc, char **argv, char *config_path_out, int config_path_sz, CliOverrides *ov) {
    memset(ov, 0, sizeof(*ov));
    config_path_out[0] = 0;

    for (int i = 1; i < argc; i++) {
        if ((_stricmp(argv[i], "-cp") == 0 || _stricmp(argv[i], "--cp") == 0 ||
             _stricmp(argv[i], "--config") == 0 || _stricmp(argv[i], "-c") == 0)
            && i + 1 < argc) {
            strncpy(config_path_out, argv[i + 1], config_path_sz - 1);
            i++;
        } else if ((_stricmp(argv[i], "--port") == 0 || _stricmp(argv[i], "-p") == 0) && i + 1 < argc) {
            ov->port = atoi(argv[i + 1]);
            ov->port_set = 1;
            i++;
        } else if (_stricmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            strncpy(ov->bind, argv[i + 1], sizeof(ov->bind) - 1);
            ov->bind_set = 1;
            i++;
        } else if ((_stricmp(argv[i], "--log") == 0 || _stricmp(argv[i], "-l") == 0) && i + 1 < argc) {
            strncpy(ov->log_path, argv[i + 1], sizeof(ov->log_path) - 1);
            ov->log_set = 1;
            i++;
        } else if (_stricmp(argv[i], "--health-interval") == 0 && i + 1 < argc) {
            ov->health_interval = atoi(argv[i + 1]);
            ov->health_interval_set = 1;
            i++;
        } else if (_stricmp(argv[i], "--version") == 0 || _stricmp(argv[i], "-v") == 0) {
            printf("proxy version %s\n", PROXY_VERSION);
            exit(0);
        }
    }
}

void apply_cli_overrides(Config *cfg, const CliOverrides *ov) {
    if (ov->port_set) cfg->listen_port = ov->port;
    if (ov->bind_set) snprintf(cfg->listen_bind, MAX_HOST_LEN, "%s", ov->bind);
    if (ov->log_set) snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", ov->log_path);
    if (ov->health_interval_set) cfg->health_interval_sec = ov->health_interval;
}
