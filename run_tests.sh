#!/bin/sh
# Host tests: Python cross-check vectors + C unit/simulation tests (ASan/UBSan).
# Needs gcc and python3. Capture-based tests skip themselves when fixtures/ is absent
# (real captures are never published).
set -e
cd "$(dirname "$0")"
OUT=${TMPDIR:-/tmp}/call277_test.$$
mkdir -p "$OUT"
python3 -I tools/crosscheck.py > "$OUT/crosscheck.txt"
CF="-std=gnu89 -Wall -Wextra -O1 -g -Isrc -Itests -fsanitize=address,undefined -fno-sanitize-recover=undefined"
L=src
LIB="$L/c277_crypto.c $L/c277_msg.c $L/c277_conn.c $L/c277_refl.c $L/c277_stun.c $L/c277_ice.c $L/c277_rtp.c $L/c277_video.c $L/c277_session.c"
gcc $CF -o "$OUT/test_call277" tests/test_call277.c $LIB
gcc $CF -o "$OUT/test_session" tests/test_session.c $LIB
gcc $CF -o "$OUT/test_video" tests/test_video.c $L/c277_video.c $L/c277_rtp.c $L/c277_crypto.c
"$OUT/test_call277" "$OUT/crosscheck.txt"
"$OUT/test_session" "$OUT/crosscheck.txt"
"$OUT/test_video"
rm -rf "$OUT"
echo "ALL HOST TESTS PASSED"
