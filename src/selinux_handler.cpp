#include "selinux_handler.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static bool g_selinux_changed = false;

bool handle_selinux_init() {
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "0", 1) == 1) {
            printf("[+] Selinux has been changed to Permissive\n");
            g_selinux_changed = true;
        }
        close(fd);
        return true;
    }
    printf("[-] Failed to open enforce\n");

    fd = open("/proc/filesystems", O_RDONLY);
    if (fd >= 0) {
        char buf[256] = {0};
        read(fd, buf, sizeof(buf));
        close(fd);
        if (strstr(buf, "selinux")) {
            printf("[-] SELinux is Enforcing\n");
            return false;
        }
    }
    printf("[+] SELinux is Permissive or Disabled\n");
    return true;
}

bool handle_selinux_restore() {
    if (!g_selinux_changed) return true;
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (fd >= 0) {
        write(fd, "1", 1);
        close(fd);
        printf("[+] SELinux has been rec\n");
        return true;
    }
    return false;
}
