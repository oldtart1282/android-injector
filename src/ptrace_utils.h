#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include <sys/types.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <cstdint>
#include <cstddef>

ssize_t ptrace_write_stack(int pid, uint64_t sp, const void* data, size_t len);
ssize_t ptrace_read(int pid, uint64_t addr, void* data, size_t len);
ssize_t ptrace_write(int pid, uint64_t addr, const void* data, size_t len);
ssize_t ptrace_write_data(int pid, uint64_t addr, const void* data, size_t len);
long find_trampoline_addr(pid_t pid, const char* segment_name);
uint64_t find_module_base(pid_t pid, const char* module_name);
uint64_t get_remote_mmap_addr(pid_t pid);
uint64_t get_remote_dlopen_addr(pid_t pid);
uint64_t get_remote_dlsym_addr(pid_t pid);
uint64_t get_remote_dlclose_addr(pid_t pid);
uint64_t get_remote_dlerror_addr(pid_t pid);
bool ptrace_attach(pid_t pid);
bool ptrace_detach(pid_t pid);
bool ptrace_getregs(pid_t pid, user_pt_regs* regs);
bool ptrace_setregs(pid_t pid, user_pt_regs* regs);
bool recover_regs(pid_t pid, user_pt_regs* orig_regs);
unsigned long call_remote_function(pid_t pid, uint64_t func_addr, const uint64_t* call_args, int arg_count, user_pt_regs* regs);
bool inject_process(pid_t pid, const char* lib_path, const char* symbol_name);

extern long g_cached_trampoline;

#endif
