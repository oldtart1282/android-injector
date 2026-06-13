#include "target_finder.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pid_t get_pid_by_name(const char* name) {
    DIR* dir;
    struct dirent* ent;
    char buf[512];
    FILE* fp;
    pid_t pid = -1;

    if (!(dir = opendir("/proc"))) {
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        long lpid = atol(ent->d_name);
        if (lpid < 1) continue;

        snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
        fp = fopen(buf, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp) != NULL) {
                if (strcmp(buf, name) == 0) {
                    pid = lpid;
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return pid;
}

bool get_pid_by_name(int* out_pid, const char* proc_name) {
    pid_t pid = get_pid_by_name(proc_name);
    if (pid > 0) {
        *out_pid = (int)pid;
        return true;
    }
    return false;
}
