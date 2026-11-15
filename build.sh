#!/usr/bin/env bash
#
# Build all AdaptixBOFKit BOFs and report which objects were produced.
set -u

cd "$(dirname "$0")"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[!] x86_64-w64-mingw32-gcc not found."
    echo "    Debian/Kali: sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64"
    exit 1
fi

make -j"$(nproc)" || exit 1

echo
echo "Built objects:"
ls -1 _bin/*.x64.o 2>/dev/null | sed 's/^/  /'
echo
printf 'Total: %s BOF(s)\n' "$(ls -1 _bin/*.x64.o 2>/dev/null | wc -l)"
