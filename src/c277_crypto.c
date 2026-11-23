/* c277_crypto.c - see c277_crypto.h. */
#include <string.h>
#include "./callproto_crypto.c"   /* AES block code + SHA-256 (reused) */
#include "c277_crypto.h"

void c277_aes256_ctr(const u8 *key32, const u8 *iv16, const u8 *in, u8 *out, u32 n)
{
    u8 rk[240], ctr[16], ks[16];
    u32 i, j, m;
    int k;
    aes_expand(key32, rk);
    memcpy(ctr, iv16, 16);
    for (i = 0; i < n; i += 16) {
        memcpy(ks, ctr, 16);
        aes_encrypt_block(rk, ks);
        m = n - i;
        if (m > 16) m = 16;
        for (j = 0; j < m; j++) out[i + j] = (u8)(in[i + j] ^ ks[j]);
        for (k = 15; k >= 0; k--) {
            if (++ctr[k] != 0) break;
        }
    }
}

/* ------------------------------------------------------------------ SHA-1 */

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(u32 *h, const u8 *p)
{
    u32 w[80], a, b, c, d, e, f, k, t;
    int i;
    for (i = 0; i < 16; i++) w[i] = be32(p + i * 4);
    for (i = 16; i < 80; i++) w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999UL; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1UL; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCUL; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6UL; }
        t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void c277_sha1_init(c277_sha1_ctx *c)
{
    c->h[0] = 0x67452301UL; c->h[1] = 0xEFCDAB89UL; c->h[2] = 0x98BADCFEUL;
    c->h[3] = 0x10325476UL; c->h[4] = 0xC3D2E1F0UL;
    c->nbuf = 0;
    c->total = 0;
}

void c277_sha1_update(c277_sha1_ctx *c, const u8 *data, u32 len)
{
    u32 n;
    c->total += len;
    if (c->nbuf) {
        n = 64 - c->nbuf;
        if (n > len) n = len;
        memcpy(c->buf + c->nbuf, data, n);
        c->nbuf += n; data += n; len -= n;
        if (c->nbuf < 64) return;
        sha1_block(c->h, c->buf);
        c->nbuf = 0;
    }
    while (len >= 64) {
        sha1_block(c->h, data);
        data += 64; len -= 64;
    }
    if (len) {
        memcpy(c->buf, data, len);
        c->nbuf = len;
    }
}

void c277_sha1_final(c277_sha1_ctx *c, u8 *out)
{
    u8 tail[128];
    u32 rest = c->nbuf, tlen;
    int i;
    memcpy(tail, c->buf, rest);
    tail[rest] = 0x80;
    tlen = (rest < 56) ? 64 : 128;
    memset(tail + rest + 1, 0, tlen - rest - 1);
    put32(tail + tlen - 8, c->total >> 29);
    put32(tail + tlen - 4, c->total << 3);
    sha1_block(c->h, tail);
    if (tlen == 128) sha1_block(c->h, tail + 64);
    for (i = 0; i < 5; i++) put32(out + i * 4, c->h[i]);
}

void c277_sha1(const u8 *data, u32 len, u8 *out)
{
    c277_sha1_ctx c;
    c277_sha1_init(&c);
    c277_sha1_update(&c, data, len);
    c277_sha1_final(&c, out);
}

void c277_hmac_sha1_init(c277_hmac_sha1_ctx *c, const u8 *key, u32 keylen)
{
    u8 k[64], ipad[64];
    int i;
    memset(k, 0, 64);
    if (keylen > 64) c277_sha1(key, keylen, k);
    else if (keylen) memcpy(k, key, keylen);
    for (i = 0; i < 64; i++) { ipad[i] = (u8)(k[i] ^ 0x36); c->opad[i] = (u8)(k[i] ^ 0x5c); }
    c277_sha1_init(&c->in);
    c277_sha1_update(&c->in, ipad, 64);
}

void c277_hmac_sha1_update(c277_hmac_sha1_ctx *c, const u8 *data, u32 len)
{
    c277_sha1_update(&c->in, data, len);
}

void c277_hmac_sha1_final(c277_hmac_sha1_ctx *c, u8 *out)
{
    u8 inner[20];
    c277_sha1_ctx o;
    c277_sha1_final(&c->in, inner);
    c277_sha1_init(&o);
    c277_sha1_update(&o, c->opad, 64);
    c277_sha1_update(&o, inner, 20);
    c277_sha1_final(&o, out);
}

/* ------------------------------------------------------------------ CRC-32 */

u32 c277_crc32_update(u32 crc, const u8 *data, u32 len)
{
    u32 i;
    int b;
    crc = ~crc;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (b = 0; b < 8; b++) crc = (crc >> 1) ^ (0xEDB88320UL & (0UL - (crc & 1)));
    }
    return ~crc;
}

/* ------------------------------------------------------------------ EncryptedConnection KDF (spec sec. 3) */

void c277_msg_key(const u8 *K, u32 x, const u8 *pt, u32 n, u8 *out16)
{
    tgc_sha256_ctx c;
    u8 h[32];
    tgc_sha256_init(&c);
    tgc_sha256_update(&c, K + 88 + x, 32);
    tgc_sha256_update(&c, pt, n);
    tgc_sha256_final(&c, h);
    memcpy(out16, h + 8, 16);
}

void c277_kdf(const u8 *K, u32 x, const u8 *mk, u8 *key, u8 *iv)
{
    tgc_sha256_ctx c;
    u8 a[32], b[32];
    tgc_sha256_init(&c);
    tgc_sha256_update(&c, mk, 16);
    tgc_sha256_update(&c, K + x, 36);
    tgc_sha256_final(&c, a);
    tgc_sha256_init(&c);
    tgc_sha256_update(&c, K + 40 + x, 36);
    tgc_sha256_update(&c, mk, 16);
    tgc_sha256_final(&c, b);
    memcpy(key, a, 8); memcpy(key + 8, b + 8, 16); memcpy(key + 24, a + 24, 8);
    memcpy(iv, b, 4); memcpy(iv + 4, a + 8, 8); memcpy(iv + 12, b + 24, 4);
}

void c277_seal(const u8 *K, u32 x, u8 *buf, u32 n)
{
    u8 key[32], iv[16];
    c277_msg_key(K, x, buf, n, buf - 16);
    c277_kdf(K, x, buf - 16, key, iv);
    c277_aes256_ctr(key, iv, buf, buf, n);
}

int c277_open(const u8 *K, u32 x, const u8 *mk, const u8 *ct, u32 n, u8 *pt)
{
    u8 key[32], iv[16], chk[16], d = 0;
    int i;
    c277_kdf(K, x, mk, key, iv);
    c277_aes256_ctr(key, iv, ct, pt, n);
    c277_msg_key(K, x, pt, n, chk);
    for (i = 0; i < 16; i++) d |= (u8)(chk[i] ^ mk[i]);
    return d ? -1 : 0;
}
