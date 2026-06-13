#ifndef TARGET_FINDER_H
#define TARGET_FINDER_H

#include <sys/types.h>

pid_t get_pid_by_name(const char* name);
bool get_pid_by_name(int* out_pid, const char* proc_name);

#endif
