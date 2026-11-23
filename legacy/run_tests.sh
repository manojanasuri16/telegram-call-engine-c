#!/bin/sh
# Host tests for the legacy (libtgvoip 2.4.4-style) call protocol code in ../src/callproto*.
set -e
cd "$(dirname "$0")"
OUT=${TMPDIR:-/tmp}/callproto_test.$$
mkdir -p "$OUT"
python3 -I tools/crosscheck.py > "$OUT/crosscheck.txt"
gcc -std=gnu89 -Wall -Wextra -O1 -g -I../src -fsanitize=address,undefined -o "$OUT/test_callproto" \
    tests/test_callproto.c ../src/callproto.c ../src/callproto_crypto.c
"$OUT/test_callproto" "$OUT/crosscheck.txt"
rm -rf "$OUT"
