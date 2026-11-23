/* c277_refl.c - see c277_refl.h. */
#include <string.h>
#include "c277_refl.h"

static void wle32(u8 *p, u32 v)
{
    p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}

static u32 rle32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

void c277_refl_own_tag(const u8 *tag16, u32 rt, u8 *out)
{
    memcpy(out, tag16, 12);
    wle32(out + 12, rt);
}

int c277_refl_build_hello(const u8 *tag16, u32 rt, u8 *out, u32 cap)
{
    if (cap < C277_REFL_HELLO_LEN) return -1;
    c277_refl_own_tag(tag16, rt, out);
    memset(out + 16, 0xFF, 12);
    out[28] = 0xFE; out[29] = 0xFF; out[30] = 0xFF; out[31] = 0xFF;
    memset(out + 32, 0, 7);
    out[39] = 0x7B;
    return C277_REFL_HELLO_LEN;
}

int c277_refl_wrap(const u8 *tag16, u32 peer_rt, u32 own_rt, const u8 *pl, u32 len, u8 *out, u32 cap)
{
    u32 total = 24 + ((len + 3) & ~3UL), i;
    if (len > 65535UL || cap < total) return -1;
    memcpy(out, tag16, 12);
    wle32(out + 12, peer_rt);
    wle32(out + 16, own_rt);
    out[20] = (u8)(len >> 24); out[21] = (u8)(len >> 16); out[22] = (u8)(len >> 8); out[23] = (u8)len;
    if (len) memcpy(out + 24, pl, len);
    for (i = 24 + len; i < total; i++) out[i] = 0;
    return (int)total;
}

void c277_refl_parse(const u8 *d, u32 n, const u8 *tag16, c277_refl_rx *rx)
{
    u32 i, len;
    rx->kind = C277_REFL_NONE; rx->control = 0; rx->sender_tag = 0;
    rx->payload = 0; rx->payload_len = 0;
    if (n < 16 || memcmp(d, tag16, 12) != 0) return;
    rx->kind = C277_REFL_READY;
    if (n >= 28) {
        for (i = 16; i < 28; i++) if (d[i] != 0xFF) break;
        if (i == 28) { rx->control = 1; return; }
    }
    if (n < 24) return;
    len = ((u32)d[20] << 24) | ((u32)d[21] << 16) | ((u32)d[22] << 8) | d[23];
    if (len > n - 24) return;
    rx->kind = C277_REFL_DATA;
    rx->sender_tag = rle32(d + 16);
    rx->payload = d + 24;
    rx->payload_len = len;
}

int c277_refl_hostname(char *out, u32 cap, u32 id, u32 tag)
{
    u32 p = 0;
    if (cap < 11 + 10 + 1 + 10 + 10) return -1;
    memcpy(out, "reflector-", 10); p = 10;
    p += c277_put_dec(out + p, id);
    out[p++] = '-';
    p += c277_put_dec(out + p, tag);
    memcpy(out + p, ".reflector", 10); p += 10;
    return (int)p;
}

static int lt(const c277_id64 *a, const c277_id64 *b)
{
    if (a->hi != b->hi) return a->hi < b->hi;
    return a->lo < b->lo;
}

u32 c277_refl_rank(const c277_id64 *ids, u32 n, u32 which)
{
    u32 i, r = 1;
    for (i = 0; i < n; i++) if (lt(&ids[i], &ids[which])) r++;
    return r;
}
