#include "common.h"

static char g_service_name[256];
static char g_config_path[512];
static CliOverrides g_overrides;
static SERVICE_STATUS_HANDLE g_status_handle = NULL;

void parse_service_args(int argc, char **argv, ServiceArgs *sa) {
    memset(sa, 0, sizeof(*sa));
    sa->action = SVC_ACTION_RUN;
    snprintf(sa->name, sizeof(sa->name), "%s", SERVICE_DEFAULT_NAME);
    snprintf(sa->description, sizeof(sa->description), "%s", SERVICE_DEFAULT_DESCRIPTION);

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--install") == 0 || _stricmp(argv[i], "-install") == 0) {
            sa->action = SVC_ACTION_INSTALL;
        } else if (_stricmp(argv[i], "--uninstall") == 0 || _stricmp(argv[i], "-uninstall") == 0) {
            sa->action = SVC_ACTION_UNINSTALL;
        } else if (_stricmp(argv[i], "--service") == 0) {
            sa->is_service = 1;
        } else if (_stricmp(argv[i], "--name") == 0 && i + 1 < argc) {
            snprintf(sa->name, sizeof(sa->name), "%s", argv[i + 1]);
            i++;
        } else if (_stricmp(argv[i], "--description") == 0 && i + 1 < argc) {
            snprintf(sa->description, sizeof(sa->description), "%s", argv[i + 1]);
            i++;
        }
    }
}

void service_set_context(const char *config_path, const CliOverrides *overrides, const char *service_name) {
    snprintf(g_config_path, sizeof(g_config_path), "%s", config_path);
    g_overrides = *overrides;
    snprintf(g_service_name, sizeof(g_service_name), "%s", service_name);
}

/* A running service can ask the SCM "which of you am I?" by matching its
   own process ID against the list of currently-tracked services. This means
   the installed command line doesn't need --name baked into it at all - it
   only matters at install/uninstall time. */
int discover_own_service_name(char *out, int outsz) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return 0;

    DWORD bytes_needed = 0, count = 0, resume = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &bytes_needed, &count, &resume, NULL);

    int found = 0;
    if (bytes_needed > 0) {
        BYTE *buf = (BYTE*)malloc(bytes_needed);
        if (buf) {
            if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                      buf, bytes_needed, &bytes_needed, &count, &resume, NULL)) {
                ENUM_SERVICE_STATUS_PROCESSA *arr = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
                DWORD my_pid = GetCurrentProcessId();
                for (DWORD i = 0; i < count; i++) {
                    if (arr[i].ServiceStatusProcess.dwProcessId == my_pid) {
                        snprintf(out, outsz, "%s", arr[i].lpServiceName);
                        found = 1;
                        break;
                    }
                }
            }
            free(buf);
        }
    }

    CloseServiceHandle(scm);
    return found;
}

static void report_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    SERVICE_STATUS st;
    memset(&st, 0, sizeof(st));
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = state;
    st.dwControlsAccepted = (state == SERVICE_START_PENDING || state == SERVICE_STOPPED) ? 0 : SERVICE_ACCEPT_STOP;
    st.dwWin32ExitCode = exit_code;
    st.dwWaitHint = wait_hint;
    if (g_status_handle) SetServiceStatus(g_status_handle, &st);
}

static DWORD WINAPI service_ctrl_handler(DWORD ctrl, DWORD event_type, LPVOID event_data, LPVOID context) {
    (void)event_type; (void)event_data; (void)context;
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        report_status(SERVICE_STOP_PENDING, 0, 3000);
        log_msg("Service stop requested - shutting down");
        report_status(SERVICE_STOPPED, 0, 0);
        ExitProcess(0);
    }
    return NO_ERROR;
}

static void WINAPI service_main(DWORD svc_argc, LPSTR *svc_argv) {
    (void)svc_argc; (void)svc_argv;

    g_status_handle = RegisterServiceCtrlHandlerExA(g_service_name, service_ctrl_handler, NULL);
    if (!g_status_handle) return;

    report_status(SERVICE_START_PENDING, 0, 3000);
    report_status(SERVICE_RUNNING, 0, 0);

    /* Same startup path as running in a console - a service is just this
       without a window, kept alive by the SCM instead of a user's shell. */
    run_proxy(g_config_path, &g_overrides);
}

int run_as_service(const char *service_name) {
    char name_buf[256];
    snprintf(name_buf, sizeof(name_buf), "%s", service_name);

    SERVICE_TABLE_ENTRYA table[] = {
        { name_buf, service_main },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(table)) {
        DWORD err = GetLastError();
        printf("Failed to start as a Windows service (error %lu).\n", (unsigned long)err);
        printf("This flag is meant to be used by the Service Control Manager, not run by hand.\n");
        printf("To run normally, start the exe without --service. To install as a service, use --install.\n");
        return 1;
    }
    return 0;
}

static void resolve_install_config_path(const char *cp_arg, char *out, int outsz) {
    if (cp_arg && cp_arg[0]) {
        char full[512];
        DWORD n = GetFullPathNameA(cp_arg, sizeof(full), full, NULL);
        if (n > 0 && n < sizeof(full)) snprintf(out, outsz, "%s", full);
        else snprintf(out, outsz, "%s", cp_arg);
    } else {
        snprintf(out, outsz, "%s", cp_arg ? cp_arg : "");
    }
}

int install_service(const ServiceArgs *sa, const char *config_path, int cp_was_explicit) {
    char exe_path[400];
    DWORD n = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    if (n == 0 || n >= sizeof(exe_path)) {
        printf("Could not determine the path of this executable.\n");
        return 1;
    }

    char binpath[1400];
    if (cp_was_explicit) {
        char abs_config[512];
        resolve_install_config_path(config_path, abs_config, sizeof(abs_config));
        snprintf(binpath, sizeof(binpath), "\"%s\" --service -cp \"%s\"", exe_path, abs_config);
        printf("Config file: %s\n", abs_config);
    } else {
        /* No -cp baked in - the service will auto-detect <exe name>.ini next
           to the exe at startup, exactly like running it normally would. */
        snprintf(binpath, sizeof(binpath), "\"%s\" --service", exe_path);
        printf("Config file: auto-detected next to the exe (same name, .ini) when the service starts\n");
    }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        DWORD err = GetLastError();
        printf("Could not open the Service Control Manager (error %lu).\n", (unsigned long)err);
        printf("Run this command from an elevated (Administrator) Command Prompt: right-click\n");
        printf("Command Prompt -> \"Run as administrator\", then repeat the same command.\n");
        return 1;
    }

    SC_HANDLE svc = CreateServiceA(
        scm, sa->name, sa->name,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binpath, NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            printf("A service named \"%s\" already exists.\n", sa->name);
            printf("Remove it first: %s --uninstall --name \"%s\"\n", exe_path, sa->name);
        } else if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied (error 5). Run this from an elevated (Administrator) Command Prompt.\n");
        } else {
            printf("Could not create the service (error %lu).\n", (unsigned long)err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_DESCRIPTIONA sd;
    sd.lpDescription = (LPSTR)sa->description;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &sd);

    printf("Service \"%s\" installed successfully.\n", sa->name);
    printf("Set to start automatically on boot. To start it right now:\n");
    printf("  net start \"%s\"\n", sa->name);
    printf("(or use Services.msc / Task Manager -> Services tab)\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int uninstall_service(const ServiceArgs *sa) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        DWORD err = GetLastError();
        printf("Could not open the Service Control Manager (error %lu).\n", (unsigned long)err);
        printf("Run this from an elevated (Administrator) Command Prompt.\n");
        return 1;
    }

    SC_HANDLE svc = OpenServiceA(scm, sa->name, SERVICE_STOP | DELETE);
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("No service named \"%s\" was found.\n", sa->name);
        } else if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied (error 5). Run this from an elevated (Administrator) Command Prompt.\n");
        } else {
            printf("Could not open service \"%s\" (error %lu).\n", sa->name, (unsigned long)err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status); /* best effort - fine if already stopped */
    Sleep(500);

    int ok = DeleteService(svc);
    if (ok) {
        printf("Service \"%s\" removed.\n", sa->name);
    } else {
        printf("Could not remove service \"%s\" (error %lu).\n", sa->name, (unsigned long)GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}
