#!/bin/sh
set -eu

CC="${CC:-gcc}"
"$CC" -O2 -static -Wall -Wextra -Werror -o exploit exploit.c
sha256sum exploit
