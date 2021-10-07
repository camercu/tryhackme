#!/bin/bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
gcc -o /tmp/libcrypt.so.1 -shared -fPIC -nostartfiles library_path.c
