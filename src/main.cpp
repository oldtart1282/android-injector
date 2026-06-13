#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include "target_finder.h"
#include "selinux_handler.h"
#include "ptrace_utils.h"
#include "am_utils.h"

static int   g_target_pid   = 0;
static char  g_lib_path[256] = {0};
static char  g_symbol_name[256] = {0};

bool check_system_libs() {
    const char* libc = "/apex/com.android.runtime/lib64/bionic/libc.so";
    const char* linker = "/apex/com.android.runtime/bin/linker64";
    const char* libdl = "/apex/com.android.runtime/lib64/bionic/libdl.so";
    const char* libdl2 = "/system/lib64/libdl.so";

    printf("[+] libc_path is %s\n", libc);
    printf("[+] linker_path value:%s\n", linker);
    printf("[+] libdl_path is %s\n", libdl);

    bool libc_ok = access(libc, F_OK) == 0;
    bool linker_ok = access(linker, F_OK) == 0;
    bool libdl_ok = access(libdl, F_OK) == 0 || access(libdl2, F_OK) == 0;

    if (libc_ok && linker_ok && libdl_ok) {
        printf("[+] system libs is OK\n");
        return true;
    }
    return false;
}

void parse_args_and_run(int argc, char **argv) {
    if (argc <= 0) {
        puts("not found target, get_pid_by_name pid faild!");
        exit(0);
    }

    bool   start_app   = false;
    char  *pkg_name    = nullptr;
    char  *lib_path    = nullptr;
    char  *symbol_name = nullptr;
    int    pid_val     = 0;

    size_t i = 0;
    do {
        char *arg = argv[i];

        if (strcmp("-p", arg) == 0) {
            if (++i >= (size_t)argc) { puts("Missing parameter -p"); exit(-1); }
            arg = argv[i];
            pid_val = atoi(arg);
        }

        if (strcmp("-s", arg) == 0) {
            start_app = true;
        }

        if (strcmp("-n", arg) == 0) {
            size_t j = i + 1;
            if (j >= (size_t)argc) { puts("Missing parameter -n"); exit(-1); }
            pkg_name = argv[j];
            arg = pkg_name;

            if (start_app) {
                char cmd[1024] = {0};
                char extra[1032] = {0};

                build_am_extra(pkg_name, extra);
                printf("app start activity is %s\n", extra);

                memcpy(cmd, "am start ", 9);
                strcat(cmd, extra);
                printf(" %s\n", cmd);
                system(cmd);
                sleep(1);

                arg = argv[j];
            }
            i = j;
        }

        if (strcmp("-so", arg) == 0) {
            if (++i >= (size_t)argc) { puts("Missing parameter -so"); exit(-1); }
            lib_path = argv[i];
        }

        if (strcmp("--symbol", arg) == 0 || strcmp("-symbols", arg) == 0) {
            if (++i >= (size_t)argc) { puts("Missing parameter --func"); exit(-1); }
            symbol_name = argv[i];
        }

        ++i;
    } while (i < (size_t)argc);

    if (pkg_name != nullptr) {
        printf("pkg name is %s\n", pkg_name);
        if (get_pid_by_name(&pid_val, pkg_name)) {
            printf("[+] get_pid_by_name pid is %d\n", pid_val);
        }
    }

    if (pid_val == 0) {
        puts("[-] not found target & get_pid_by_name pid faild !");
        exit(0);
    }

    g_target_pid = pid_val;

    if (lib_path != nullptr) {
        printf("lib path is %s\n", lib_path);
        strcpy(g_lib_path, strdup(lib_path));
    }

    if (symbol_name != nullptr) {
        printf("symbol is %s\n", symbol_name);
        strcpy(g_symbol_name, strdup(symbol_name));
    }
}

int main(int argc, char** argv) {
    handle_selinux_init();
    printf("[+] handle_selinux_init is OK\n");

    parse_args_and_run(argc, argv);
    printf("[+] handle_parameter is OK\n");

    if (strlen(g_lib_path) == 0) {
        fprintf(stderr, "[-] Library path missing. Use -so <lib_path>\n");
        return 1;
    }

    if (access(g_lib_path, F_OK) != 0) {
        fprintf(stderr, "[-] Library file not found at %s\n", g_lib_path);
        return 1;
    }

    check_system_libs();

    printf("[+] LibPath = %s\n", g_lib_path);
    if (strlen(g_symbol_name) > 0) {
        printf("[+] func symbols is %s\n", g_symbol_name);
    }

    printf("[+] Target PID: %d\n", g_target_pid);
    printf("[+] Start Inject with %s\n", g_lib_path);

    const char* sym = strlen(g_symbol_name) > 0 ? g_symbol_name : nullptr;
    if (!inject_process(g_target_pid, g_lib_path, sym)) {
        printf("[-] Inject Erro\n");
        handle_selinux_restore();
        return 1;
    }

    handle_selinux_restore();
    return 0;
}
