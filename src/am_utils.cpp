#include "am_utils.h"
#include <cstdio>

void build_am_extra(const char* pkg_name, char* out_buf) {
    snprintf(out_buf, 1024, "-n %s/.MainActivity -a android.intent.action.MAIN -c android.intent.category.LAUNCHER", pkg_name);
}
