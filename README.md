# Android ARM64 Shared Library Injector

A lightweight native injector for Android ARM64 (AArch64) built for Termux. Uses `ptrace` to attach to a remote process, allocate memory via remote `mmap`, write a library path into the target, and call `dlopen` / `dlsym` from within the remote process.

## Tree

```
injector/
├── build.sh
├── out/
│   └── inject
└── src/
    ├── main.cpp
    ├── target_finder.cpp
    ├── target_finder.h
    ├── selinux_handler.cpp
    ├── selinux_handler.h
    ├── ptrace_utils.cpp
    ├── ptrace_utils.h
    ├── am_utils.cpp
    └── am_utils.h
```

## Build

```bash
chmod +x build.sh
./build.sh
```

Requires `clang++` (available in Termux via `pkg install clang`). No Android NDK needed.

## Requirements

- Android ARM64 device
- Termux with `clang` installed
- Root / `su` access (ptrace and SELinux manipulation require root)
- Target process must be running and debuggable (or SELinux set to Permissive)

## Usage

```bash
su -c ./out/inject [OPTIONS]
```

### Flags

| Flag | Argument | Description |
|------|----------|-------------|
| `-p` | `<pid>` | Target process PID. |
| `-n` | `<package>` | Target package name (e.g. `com.tencent.ig`). |
| `-s` | — | Start the target package via `am start` before attaching. Must be used with `-n`. |
| `-so` | `<path>` | Full path to the `.so` library to inject. **Required.** |
| `--symbol` | `<name>` | Function symbol inside the injected library to resolve and execute after `dlopen`. Pass `symbols` to skip calling any function. |

### Examples

**Inject by PID:**
```bash
su -c ./out/inject -p 1234 -so /data/local/tmp/libtest.so
```

**Inject by package name:**
```bash
su -c ./out/inject -n com.tencent.ig -so /data/local/tmp/libtest.so
```

**Start app, then inject by package name:**
```bash
su -c ./out/inject -s -n com.tencent.ig -so /data/local/tmp/libtest.so
```

**Inject and call a specific exported function:**
```bash
su -c ./out/inject -n com.tencent.ig -so /data/local/tmp/libtest.so --symbol MyInitFunc
```

**Inject without calling any exported function:**
```bash
su -c ./out/inject -n com.tencent.ig -so /data/local/tmp/libtest.so --symbol symbols
```

## How It Works

1. **SELinux** — Sets SELinux to Permissive if it is Enforcing. Restores it to Enforcing after injection.
2. **Attach** — `ptrace(PTRACE_ATTACH)` to the target PID.
3. **Get Registers** — Saves the original `user_pt_regs` context.
4. **Resolve Remote Addresses** — Calculates the remote addresses of `mmap`, `dlopen`, `dlsym`, `dlclose`, and `dlerror` by comparing local and remote linker base addresses.
5. **Remote mmap** — Calls `mmap` in the target to allocate an RWX anonymous region.
6. **Write Path** — Writes the library path string into the allocated remote memory.
7. **Remote dlopen** — Calls `dlopen` in the target with the written path.
8. **Remote dlsym** *(optional)* — If a symbol is provided, calls `dlsym` to resolve it, then calls the resolved function.
9. **Remote dlclose** — Calls `dlclose` on the handle.
10. **Restore & Detach** — Restores original registers, verifies them, and detaches.

## Notes

- The injector uses `PTRACE_SETREGSET` / `PTRACE_GETREGSET` with `NT_PRSTATUS` on AArch64. `PTRACE_SETREGS` is not available on ARM64 Android.
- Stack arguments beyond x0-x7 are written via `process_vm_writev`.
- On Android 8+ (SDK > 23), the LR register is set to a trampoline address to catch the return from the injected call.
- The target process must be stopped before injection. If the target is heavily protected, additional anti-debug bypasses may be needed.

## Troubleshooting

| Issue | Cause / Fix |
|-------|-------------|
| `ptrace attach process error` | Target is already being traced, or you lack root. Run under `su`. |
| `Failed to open enforce` | SELinux node is not accessible. Check root access. |
| `get_remote_func_addr` returns 0 | Target linker64 is not mapped yet, or the target is 32-bit (this injector is 64-bit only). |
| `dlopen error` | The `.so` path is wrong, the library is not compiled for the target ABI, or dependencies are missing. Check logcat. |
| `Call Remote mmap Func Failed` | The target may have seccomp or ptrace restrictions. Try on a less restricted process first. |
