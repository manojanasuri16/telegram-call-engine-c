/* c277_stun.c - see c277_stun.h. */
#include <string.h>
#include "c277_stun.h"

static u32 g16(const u8 *p) { return ((u32)p[0] << 8) | p[1]; }
static u32 g32(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
static void p16(u8 *p, u32 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void p32(u8 *p, u32 v)
{
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}

int c277_stun_is_stun(const u8 *d, u32 n)
{
    return n >= 20 && (d[0] & 0xC0) == 0 && g32(d + 4) == C277_STUN_COOKIE;
}

int c277_stun_parse(const u8 *d, u32 n, c277_stun_msg *m)
{
    u32 len, pos, t, l;
    memset(m, 0, sizeof(*m));
    m->mi_off = -1; m->fp_off = -1;
    if (!c277_stun_is_stun(d, n)) return -1;
    len = g16(d + 2);
    if ((len & 3) || n != 20 + len) return -1;
    m->type = g16(d);
    memcpy(m->txid, d + 8, 12);
    pos = 20;
    while (pos < n) {
        if (n - pos < 4) return -1;
        t = g16(d + pos); l = g16(d + pos + 2);
        if (l > n - pos - 4) return -1;
        switch (t) {
        case 0x0006: m->username = d + pos + 4; m->username_len = l; break;
        case 0x0024: if (l == 4) { m->has_priority = 1; m->priority = g32(d + pos + 4); } break;
        case 0x802A: if (l == 8) { m->controlling = 1; memcpy(m->tiebreak, d + pos + 4, 8); } break;
        case 0x8029: if (l == 8) { m->controlled = 1; memcpy(m->tiebreak, d + pos + 4, 8); } break;
        case 0x0025: m->use_candidate = 1; break;
        case 0x0020:
            if (l >= 8 && d[pos + 5] == 1) {
                m->has_mapped = 1;
                m->mapped_port = g16(d + pos + 6) ^ (C277_STUN_COOKIE >> 16);
                m->mapped_ip = g32(d + pos + 8) ^ C277_STUN_COOKIE;
            }
            break;
        case 0x0009: if (l >= 4) m->error_code = (int)((d[pos + 6] & 7) * 100 + d[pos + 7]); break;
        case 0x0008: if (l == 20 && m->mi_off < 0) m->mi_off = (int)pos; break;
        case 0x8028: if (l == 4 && m->fp_off < 0) m->fp_off = (int)pos; break;
        default: break;   /* GOOG-NETWORK-INFO, SOFTWARE, NOMINATION, ... */
        }
        pos += 4 + ((l + 3) & ~3UL);
    }
    return pos == n ? 0 : -1;
}

int c277_stun_check_fingerprint(const u8 *d, u32 n, const c277_stun_msg *m)
{
    u32 crc;
    if (m->fp_off < 0 || (u32)m->fp_off + 8 != n) return 0;
    crc = c277_crc32_update(0, d, (u32)m->fp_off) ^ 0x5354554EUL;
    return crc == g32(d + m->fp_off + 4);
}

int c277_stun_check_integrity(const u8 *d, u32 n, const c277_stun_msg *m, const u8 *key, u32 keylen)
{
    c277_hmac_sha1_ctx h;
    u8 lenb[2], mac[20], diff = 0;
    u32 mi = (u32)m->mi_off, i;
    (void)n;
    if (m->mi_off < 0) return 0;
    p16(lenb, mi + 24 - 20);
    c277_hmac_sha1_init(&h, key, keylen);
    c277_hmac_sha1_update(&h, d, 2);
    c277_hmac_sha1_update(&h, lenb, 2);
    c277_hmac_sha1_update(&h, d + 4, mi - 4);
    c277_hmac_sha1_final(&h, mac);
    for (i = 0; i < 20; i++) diff |= (u8)(mac[i] ^ d[mi + 4 + i]);
    return diff == 0;
}

/* --- builder helpers: *pos is the write offset, header length kept in sync later */

static int attr(u8 *out, u32 cap, u32 *pos, u32 type, const u8 *v, u32 l)
{
    u32 pad = (4 - (l & 3)) & 3;
    if (cap - *pos < 4 + l + pad) return -1;
    p16(out + *pos, type); p16(out + *pos + 2, l);
    if (l) memcpy(out + *pos + 4, v, l);
    memset(out + *pos + 4 + l, 0, pad);
    *pos += 4 + l + pad;
    return 0;
}

static int header(u8 *out, u32 cap, u32 type, const u8 *txid)
{
    if (cap < 20) return -1;
    p16(out, type); p16(out + 2, 0); p32(out + 4, C277_STUN_COOKIE);
    memcpy(out + 8, txid, 12);
    return 0;
}

/* MESSAGE-INTEGRITY then FINGERPRINT */
static int trailer(u8 *out, u32 cap, u32 *pos, const u8 *key, u32 keylen)
{
    c277_hmac_sha1_ctx h;
    u8 mac[20], fp[4];
    if (cap - *pos < 24 + 8) return -1;
    p16(out + 2, *pos - 20 + 24);
    c277_hmac_sha1_init(&h, key, keylen);
    c277_hmac_sha1_update(&h, out, *pos);
    c277_hmac_sha1_final(&h, mac);
    attr(out, cap, pos, 0x0008, mac, 20);
    p16(out + 2, *pos - 20 + 8);
    p32(fp, c277_crc32_update(0, out, *pos) ^ 0x5354554EUL);
    attr(out, cap, pos, 0x8028, fp, 4);
    return (int)*pos;
}

int c277_stun_build_request(u8 *out, u32 cap, const u8 *txid12,
                            const u8 *username, u32 username_len, u32 priority,
                            int controlling, const u8 *tiebreak8, int use_candidate,
                            const u8 *key, u32 keylen)
{
    u32 pos = 20;
    u8 pr[4];
    if (header(out, cap, C277_STUN_BIND_REQ, txid12) < 0) return -1;
    p32(pr, priority);
    if (attr(out, cap, &pos, 0x0006, username, username_len) ||
        attr(out, cap, &pos, 0x0024, pr, 4) ||
        attr(out, cap, &pos, controlling ? 0x802A : 0x8029, tiebreak8, 8) ||
        (use_candidate && attr(out, cap, &pos, 0x0025, 0, 0)))
        return -1;
    return trailer(out, cap, &pos, key, keylen);
}

int c277_stun_build_success(u8 *out, u32 cap, const u8 *txid12, const char *software,
                            u32 ip_host, u32 port, const u8 *key, u32 keylen)
{
    u32 pos = 20;
    u8 xa[8];
    if (header(out, cap, C277_STUN_BIND_OK, txid12) < 0) return -1;
    if (software && attr(out, cap, &pos, 0x8022, (const u8 *)software, (u32)strlen(software)))
        return -1;
    xa[0] = 0; xa[1] = 1;
    p16(xa + 2, port ^ (C277_STUN_COOKIE >> 16));
    p32(xa + 4, ip_host ^ C277_STUN_COOKIE);
    if (attr(out, cap, &pos, 0x0020, xa, 8)) return -1;
    return trailer(out, cap, &pos, key, keylen);
}
