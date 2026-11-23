/* callproto_crypto.h - AES-256-IGE + SHA-256 for the Telegram legacy call
 * protocol. Code copied from native/tgnative/tgnative.c (verified vs
 * Python/OpenSSL there); behaviour identical. C89, no malloc, no writable
 * static data, no floating point. */
#ifndef CALLPROTO_CRYPTO_H
#define CALLPROTO_CRYPTO_H

#ifndef TGCP_TYPES_DEFINED
#define TGCP_TYPES_DEFINED
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
#endif

/* MTProto IGE (OpenSSL AES_ige_encrypt convention). n must be a multiple of
 * 16. iv[32]: encrypt: iv[0..16) = previous ciphertext (y0), iv[16..32) =
 * previous plaintext (x0); decrypt uses the same 32-byte iv. in == out is OK. */
void tgc_ige(const u8 *in, u8 *out, int n, const u8 *key32, const u8 *iv32, int decrypt);

typedef struct {
    u32 h[8];
    u8  buf[64];
    u32 nbuf;
    u32 total;   /* bytes hashed so far (< 512 MB) */
} tgc_sha256_ctx;

void tgc_sha256_init(tgc_sha256_ctx *c);
void tgc_sha256_update(tgc_sha256_ctx *c, const u8 *data, u32 len);
void tgc_sha256_final(tgc_sha256_ctx *c, u8 *out32);
void tgc_sha256(const u8 *data, u32 len, u8 *out32);

#endif
