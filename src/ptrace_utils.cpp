#include "ptrace_utils.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/system_properties.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <linux/elf.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

long g_cached_trampoline = 0;

ssize_t ptrace_write_stack(int pid, uint64_t sp, const void* data, size_t len) {
    struct iovec local_iov = { const_cast<void*>(data), len };
    struct iovec remote_iov = { reinterpret_cast<void*>(sp), len };
    return process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
}

ssize_t ptrace_read(int pid, uint64_t addr, void* data, size_t len) {
    struct iovec local_iov = { data, len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

ssize_t ptrace_write(int pid, uint64_t addr, const void* data, size_t len) {
    struct iovec local_iov = { const_cast<void*>(data), len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    return process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
}

ssize_t ptrace_write_data(int pid, uint64_t addr, const void* data, size_t len) {
    const uint8_t* src = reinterpret_cast<const uint8_t*>(data);
    size_t written = 0;
    while (written < len) {
        size_t remain = len - written;
        size_t chunk = remain > 8 ? 8 : remain;
        uint64_t value = 0;
        memcpy(&value, src + written, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(addr + written), reinterpret_cast<void*>(value)) < 0) {
            return -1;
        }
        written += chunk;
    }
    return (ssize_t)len;
}

long find_trampoline_addr(pid_t pid, const char* segment_name) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char line[512];
    long addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, segment_name) || strstr(line, "r-xp")) {
            unsigned long start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                addr = (long)(start + 0x1000);
                break;
            }
        }
    }
    fclose(fp);
    return addr;
}

uint64_t find_module_base(pid_t pid, const char* module_name) {
    char maps_path[256];
    if (pid == -1) {
        snprintf(maps_path, sizeof(maps_path), "/proc/self/maps");
    } else {
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    }
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            unsigned long start = 0, end = 0;
            if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
                printf("[-] sscanf error\n");
                continue;
            }
            base = start;
            break;
        }
    }
    fclose(fp);
    return base;
}

uint64_t get_remote_mmap_addr(pid_t pid) {
    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    const char* linker_path = "/apex/com.android.runtime/bin/linker64";
    if (sdk < 0x18) {
        linker_path = "/system/bin/linker64";
    }

    uint64_t local_base = find_module_base(-1, linker_path);
    uint64_t remote_base = find_module_base(pid, linker_path);
    if (local_base == 0 || remote_base == 0) return 0;

    uint64_t local_func = (uint64_t)mmap;
    uint64_t offset = local_func - local_base;
    uint64_t remote_func = remote_base + offset;

    printf("[+] [get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX\n",
           (unsigned long)local_base, (unsigned long)remote_base, (unsigned long)local_func, (unsigned long)remote_func);
    printf("[+] mmap RemoteFuncAddr:0x%lx\n", (unsigned long)remote_func);
    return remote_func;
}

uint64_t get_remote_dlopen_addr(pid_t pid) {
    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    const char* linker_path = "/apex/com.android.runtime/bin/linker64";
    if (sdk < 0x18) {
        linker_path = "/system/bin/linker64";
    }

    printf("[+] linker_path value:%s\n", linker_path);

    uint64_t local_base = find_module_base(-1, linker_path);
    uint64_t remote_base = find_module_base(pid, linker_path);
    if (local_base == 0 || remote_base == 0) return 0;

    uint64_t local_func = (uint64_t)dlopen;
    uint64_t offset = local_func - local_base;
    uint64_t remote_func = remote_base + offset;

    printf("[+] [get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX\n",
           (unsigned long)local_base, (unsigned long)remote_base, (unsigned long)local_func, (unsigned long)remote_func);
    printf("[+] dlopen RemoteFuncAddr:0x%lx\n", (unsigned long)remote_func);
    return remote_func;
}

uint64_t get_remote_dlsym_addr(pid_t pid) {
    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    const char* linker_path = "/apex/com.android.runtime/bin/linker64";
    if (sdk < 0x18) {
        linker_path = "/system/bin/linker64";
    }

    uint64_t local_base = find_module_base(-1, linker_path);
    uint64_t remote_base = find_module_base(pid, linker_path);
    if (local_base == 0 || remote_base == 0) return 0;

    uint64_t local_func = (uint64_t)dlsym;
    uint64_t offset = local_func - local_base;
    uint64_t remote_func = remote_base + offset;

    printf("[+] [get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX\n",
           (unsigned long)local_base, (unsigned long)remote_base, (unsigned long)local_func, (unsigned long)remote_func);
    printf("[+] dlsym RemoteFuncAddr:0x%lx\n", (unsigned long)remote_func);
    return remote_func;
}

uint64_t get_remote_dlclose_addr(pid_t pid) {
    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    const char* linker_path = "/apex/com.android.runtime/bin/linker64";
    if (sdk < 0x18) {
        linker_path = "/system/bin/linker64";
    }

    uint64_t local_base = find_module_base(-1, linker_path);
    uint64_t remote_base = find_module_base(pid, linker_path);
    if (local_base == 0 || remote_base == 0) return 0;

    uint64_t local_func = (uint64_t)dlclose;
    uint64_t offset = local_func - local_base;
    uint64_t remote_func = remote_base + offset;

    printf("[+] [get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX\n",
           (unsigned long)local_base, (unsigned long)remote_base, (unsigned long)local_func, (unsigned long)remote_func);
    printf("[+] dlclose RemoteFuncAddr:0x%lx\n", (unsigned long)remote_func);
    return remote_func;
}

uint64_t get_remote_dlerror_addr(pid_t pid) {
    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    const char* linker_path = "/apex/com.android.runtime/bin/linker64";
    if (sdk < 0x18) {
        linker_path = "/system/bin/linker64";
    }

    uint64_t local_base = find_module_base(-1, linker_path);
    uint64_t remote_base = find_module_base(pid, linker_path);
    if (local_base == 0 || remote_base == 0) return 0;

    uint64_t local_func = (uint64_t)dlerror;
    uint64_t offset = local_func - local_base;
    uint64_t remote_func = remote_base + offset;

    printf("[+] [get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX\n",
           (unsigned long)local_base, (unsigned long)remote_base, (unsigned long)local_func, (unsigned long)remote_func);
    printf("[+] dlerror RemoteFuncAddr:0x%lx\n", (unsigned long)remote_func);
    return remote_func;
}

bool ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        printf("[-] ptrace attach process error, pid:%d, err:%s\n", pid, strerror(errno));
        return false;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("[+] attach porcess success, pid:%d\n", pid);
    return true;
}

bool ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) < 0) {
        printf("[-] detach process error, pid:%d, err:%s\n", pid, strerror(errno));
        return false;
    }
    printf("[+] detach process success, pid:%d\n", pid);
    return true;
}

bool ptrace_getregs(pid_t pid, user_pt_regs* regs) {
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        printf("[-] ptrace_getregs: Can not get register values, io %llx, %d\n", (unsigned long long)regs, pid);
        return false;
    }
    return true;
}

bool ptrace_setregs(pid_t pid, user_pt_regs* regs) {
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        printf("[-] ptrace_setregs: Can not get register values\n");
        printf("[-] Set Regs Error\n");
        return false;
    }
    return true;
}

bool recover_regs(pid_t pid, user_pt_regs* orig_regs) {
    if (ptrace_setregs(pid, orig_regs)) {
        printf("[+] Recover Regs Success\n");
        return true;
    }
    printf("[-] Recover reges failed\n");
    return false;
}

unsigned long call_remote_function(pid_t pid, uint64_t func_addr, const uint64_t* call_args, int arg_count, user_pt_regs* regs) {
    size_t copy_count = arg_count;
    if (arg_count > 0) {
        size_t in_regs = (arg_count - 1 < 6) ? (size_t)arg_count : 8;

        for (size_t r = 0; r < in_regs; ++r)
            regs->regs[r] = call_args[r];

        copy_count = in_regs;

        if (copy_count < (size_t)arg_count) {
            size_t extra = arg_count - in_regs;
            regs->sp -= extra * 8;
            if (ptrace_write_stack(pid, regs->sp, &call_args[in_regs], extra * 8) == -1) {
                return (unsigned long)-1;
            }
        }
    }

    if ((func_addr & 1) == 0) {
        regs->pc = func_addr;
        regs->pstate &= 0xFFFFFFDF;
    } else {
        regs->pc = func_addr & ~1ULL;
        regs->pstate |= 0x20;
    }

    regs->regs[30] = 0;

    char sdk_str[16] = {0};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    long trampoline = 0;
    if (sdk > 23) {
        if (g_cached_trampoline == 0) {
            g_cached_trampoline = find_trampoline_addr(pid, "LOAD2");
        }
        trampoline = g_cached_trampoline;
    }
    regs->regs[30] = trampoline;

    if (ptrace_setregs(pid, regs) == false) {
        printf("[-] ptrace set regs or continue error, pid:%d\n", pid);
        return (unsigned long)-1;
    }

    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        printf("[-] ptrace continue process error, pid:%d, err:%ss\n", pid, strerror(errno));
        puts("[-] ptrace call error");
        return (unsigned long)-1;
    }
    printf("[+] ptrace continue process success, pid:%d\n", pid);

    int status = 0;
    waitpid(pid, &status, 0);
    printf("[+] ptrace call ret status is %d\n", status);

    while (true) {
        if (WIFSTOPPED(status) || (status & 0x7f) == 0x7f) {
            if (ptrace_getregs(pid, regs) == false) {
                printf("[-] ptrace getregs: Can not get register values\n");
                puts("[-] After call getregs error");
                return (unsigned long)-1;
            }
            return 0;
        }

        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
            printf("[-] ptrace continue process error, pid:%d, err:%ss\n", pid, strerror(errno));
            puts("[-] ptrace call error");
            return (unsigned long)-1;
        }
        printf("[+] ptrace continue process success, pid:%d\n", pid);
        waitpid(pid, &status, 0);
    }
}

bool inject_process(pid_t pid, const char* lib_path, const char* symbol_name) {
    user_pt_regs orig_regs, regs;

    if (!ptrace_attach(pid)) {
        return false;
    }

    if (!ptrace_getregs(pid, &orig_regs)) {
        ptrace_detach(pid);
        return false;
    }

    memcpy(&regs, &orig_regs, sizeof(regs));

    uint64_t mmap_addr = get_remote_mmap_addr(pid);
    if (mmap_addr == 0) {
        printf("[-] get_remote_mmap_addr failed\n");
        recover_regs(pid, &orig_regs);
        ptrace_detach(pid);
        return false;
    }

    uint64_t dlopen_addr = get_remote_dlopen_addr(pid);
    uint64_t dlsym_addr = get_remote_dlsym_addr(pid);
    uint64_t dlclose_addr = get_remote_dlclose_addr(pid);
    uint64_t dlerror_addr = get_remote_dlerror_addr(pid);

    printf("[+] Get imports: dlopen=%x dlsym=%x dlclose=%x dlerror=%x\n",
           (unsigned int)dlopen_addr, (unsigned int)dlsym_addr, (unsigned int)dlclose_addr, (unsigned int)dlerror_addr);

    uint64_t mmap_args[6] = {
        0, 0x4000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        (uint64_t)-1, 0
    };

    if (call_remote_function(pid, mmap_addr, mmap_args, 6, &regs) != 0) {
        printf("[-] Call Remote mmap Func Failed, err:%s\n", strerror(errno));
        recover_regs(pid, &orig_regs);
        ptrace_detach(pid);
        return false;
    }

    uint64_t map_addr = regs.regs[0];
    printf("[+] ptrace_call mmap success, return value=%lX, pc=%lX\n", (unsigned long)map_addr, (unsigned long)regs.pc);
    printf("[+] Remote Process Map Memory Addr:0x%lx\n", (unsigned long)map_addr);

    printf("[+] LibPath = %s\n", lib_path);

    size_t path_len = strlen(lib_path) + 1;
    if (ptrace_write_data(pid, map_addr, lib_path, path_len) != (ssize_t)path_len) {
        printf("[-] Write LibPath:%s to RemoteProcess error\n", lib_path);
        recover_regs(pid, &orig_regs);
        ptrace_detach(pid);
        return false;
    }

    uint64_t dlopen_args[2] = { map_addr, RTLD_NOW };
    if (call_remote_function(pid, dlopen_addr, dlopen_args, 2, &regs) != 0) {
        printf("[+] Call Remote dlopen Func Failed\n");
        recover_regs(pid, &orig_regs);
        ptrace_detach(pid);
        return false;
    }

    uint64_t handle = regs.regs[0];
    printf("[+] ptrace_call dlopen success, Remote Process load module Addr:0x%lx\n", (unsigned long)handle);

    if (handle == 0) {
        printf("[-] dlopen error\n");
        if (dlerror_addr != 0) {
            if (call_remote_function(pid, dlerror_addr, nullptr, 0, &regs) == 0) {
                char err_buf[256] = {0};
                uint64_t err_ptr = regs.regs[0];
                for (size_t i = 0; i < sizeof(err_buf); i += 8) {
                    long word = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(err_ptr + i), nullptr);
                    if (word < 0 && errno) break;
                    memcpy(err_buf + i, &word, 8);
                }
                printf("[-] dlopen error:%s\n", err_buf);
            } else {
                printf("[-] Call Remote dlerror Func Failed\n");
            }
        }
        recover_regs(pid, &orig_regs);
        ptrace_detach(pid);
        return false;
    }

    if (symbol_name == nullptr || strcmp(symbol_name, "symbols") == 0) {
        printf("[+] No func !!\n");
    } else {
        printf("[+] func symbols is %s\n", symbol_name);
        printf("[+] Have func !!\n");

        size_t sym_len = strlen(symbol_name) + 1;
        uint64_t sym_addr = map_addr + 0x2000;
        if (ptrace_write_data(pid, sym_addr, symbol_name, sym_len) != (ssize_t)sym_len) {
            printf("[-] Write FunctionName:%s to RemoteProcess error\n", symbol_name);
            recover_regs(pid, &orig_regs);
            ptrace_detach(pid);
            return false;
        }

        uint64_t dlsym_args[2] = { handle, sym_addr };
        if (call_remote_function(pid, dlsym_addr, dlsym_args, 2, &regs) != 0) {
            printf("[-] Call Remote dlsym Func Failed\n");
            recover_regs(pid, &orig_regs);
            ptrace_detach(pid);
            return false;
        }

        uint64_t func_addr = regs.regs[0];
        printf("[+] ptrace_call dlsym success, Remote Process ModuleFunc Addr:0x%lx\n", (unsigned long)func_addr);

        if (func_addr != 0) {
            if (call_remote_function(pid, func_addr, nullptr, 0, &regs) != 0) {
                printf("[-] Call Remote injected Func Failed\n");
                recover_regs(pid, &orig_regs);
                ptrace_detach(pid);
                return false;
            }
        }
    }

    if (dlclose_addr != 0) {
        printf("[+] dlclose RemoteFuncAddr:0x%lx\n", (unsigned long)dlclose_addr);
        uint64_t dlclose_args[1] = { handle };
        call_remote_function(pid, dlclose_addr, dlclose_args, 1, &regs);
    }

    if (recover_regs(pid, &orig_regs)) {
        printf("[+] Recover Regs Success\n");
    }

    user_pt_regs check_regs;
    if (ptrace_getregs(pid, &check_regs)) {
        if (memcmp(&orig_regs, &check_regs, sizeof(orig_regs)) != 0) {
            printf("[-] Set Regs Error\n");
        }
    }

    ptrace_detach(pid);
    printf("[+] Finish Inject\n");
    return true;
}
