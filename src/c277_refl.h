/* c277_refl.h - ReflectorPort client framing (spec sec. 2.1, 2.2; tgcalls
 * v2/ReflectorPort.cpp pin 545f5ae). IPv4/UDP only; no sockets here. */
#ifndef C277_REFL_H
#define C277_REFL_H

#include "c277_msg.h"

#define C277_REFL_HELLO_LEN 40

/* own tag16 = tag12 || LE32(random_tag) (pin:155-171) */
void c277_refl_own_tag(const u8 *peer_tag16, u32 random_tag, u8 *out16);

/* HELLO (pin:317-355): ownTag16 | FF*12 | FE FF FF FF | u64 BE 123. Returns 40 or -1. */
int c277_refl_build_hello(const u8 *peer_tag16, u32 random_tag, u8 *out, u32 cap);

/* DATA out (pin:611-675): tag12 | LE32(peer_rt) | LE32(own_rt) | BE32(len) | payload | 00 pad (to x4).
 * Returns total length or -1. */
int c277_refl_wrap(const u8 *peer_tag16, u32 peer_rt, u32 own_rt,
                   const u8 *payload, u32 len, u8 *out, u32 cap);

#define C277_REFL_NONE    0   /* not from our reflector session (ignore) */
#define C277_REFL_READY   1   /* valid but no data payload (hello reply / control) */
#define C277_REFL_DATA    2

typedef struct {
    int kind;
    int control;          /* 1 if bytes 16..28 are all FF */
    u32 sender_tag;       /* LE32 at offset 16 (data only) */
    const u8 *payload;
    u32 payload_len;
} c277_refl_rx;

/* Classify a datagram that came from exactly the server ip:port (the caller
 * checks the address). READY condition (pin:706-753): n >= 16 and the first 12
 * bytes equal tag12. Data (pin:755-791): n >= 24, BE32 len at 20 <= n-24; the
 * LE32 at offset 12 (our randomTag) is not enforced (spec: "accept iff
 * len <= size-24"). Control replies (>= 28 bytes, 16..28 all FF) are never data. */
void c277_refl_parse(const u8 *d, u32 n, const u8 *peer_tag16, c277_refl_rx *rx);

/* Candidate hostname "reflector-<id>-<tag>.reflector" (no NUL counted). */
int c277_refl_hostname(char *out, u32 cap, u32 id, u32 tag);

/* ids are signed 64-bit phoneConnection ids split in halves */
typedef struct { int hi; u32 lo; } c277_id64;
/* 1-based rank of ids[which] among ids[0..n) ascending (signed), ties share rank
 * (VoIPService.java:3590-3606, calls_call.cpp:77-88). */
u32 c277_refl_rank(const c277_id64 *ids, u32 n, u32 which);

#endif
