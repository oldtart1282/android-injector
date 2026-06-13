#!/bin/bash
set -e
mkdir -p out
clang++ -std=c++17 -O2 -D_GNU_SOURCE -fPIE -pie -o out/inject \
    src/main.cpp \
    src/target_finder.cpp \
    src/selinux_handler.cpp \
    src/ptrace_utils.cpp \
    src/am_utils.cpp
chmod +x out/inject
echo "[+] Built: out/inject"
