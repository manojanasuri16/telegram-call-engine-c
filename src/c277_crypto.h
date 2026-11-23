/* c277_crypto.h - crypto glue for the Telegram call library "2.7.7"
 * (tgcalls EncryptedConnection / STUN). See docs/CALL-277-SPEC.md.
 * C89, no malloc, no writable static data, no floating point.
 * NOTE: c277_crypto.c #includes ./callproto_crypto.c to reuse its
 * AES-256 block code and SHA-256; it therefore also defines the tgc_*
 * symbols (tgc_ige, tgc_sha256*). Do NOT link callproto_crypto.c in the
 * same image as c277_crypto.c. */
#ifndef C277_CRYPTO_H
#define C277_CRYPTO_H

#include "./callproto_crypto.h"

/* AES-256-CTR: iv16 is a 128-bit big-endian counter (no nonce split) that
 * starts at iv16 and is incremented per 16-byte block. in == out is OK. */
void c277_aes256_ctr(const u8 *key32, const u8 *iv16, const u8 *in, u8 *out, u32 n);

/* SHA-1 */
typedef struct {
    u32 h[5];
    u8  buf[64];
    u32 nbuf;
    u32 total;
} c277_sha1_ctx;
void c277_sha1_init(c277_sha1_ctx *c);
void c277_sha1_update(c277_sha1_ctx *c, const u8 *data, u32 len);
void c277_sha1_final(c277_sha1_ctx *c, u8 *out20);
void c277_sha1(const u8 *data, u32 len, u8 *out20);

/* HMAC-SHA1, incremental */
typedef struct {
    c277_sha1_ctx in;
    u8 opad[64];
} c277_hmac_sha1_ctx;
void c277_hmac_sha1_init(c277_hmac_sha1_ctx *c, const u8 *key, u32 keylen);
void c277_hmac_sha1_update(c277_hmac_sha1_ctx *c, const u8 *data, u32 len);
void c277_hmac_sha1_final(c277_hmac_sha1_ctx *c, u8 *out20);

/* CRC-32 (IEEE, zlib compatible, bitwise). Chain: crc = c277_crc32_update(crc, p, n)
 * starting from crc = 0; the result is the finished zlib.crc32 value. */
u32 c277_crc32_update(u32 crc, const u8 *data, u32 len);

/* EncryptedConnection primitives (spec sec. 3). K = 256-byte key, x = KDF offset
 * (see c277_conn.h). */
void c277_msg_key(const u8 *K, u32 x, const u8 *pt, u32 n, u8 *out16);
void c277_kdf(const u8 *K, u32 x, const u8 *msg_key16, u8 *aes_key32, u8 *aes_iv16);
/* buf[-16 .. -1] receives msgKey; buf[0..n) plaintext is encrypted in place. */
void c277_seal(const u8 *K, u32 x, u8 *buf, u32 n);
/* in: msg_key16 || ct[n]; writes pt[n]; returns 0 if msgKey verifies, else -1.
 * in == pt+... aliasing not allowed. */
int c277_open(const u8 *K, u32 x, const u8 *msg_key16, const u8 *ct, u32 n, u8 *pt);

#endif
