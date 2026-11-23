/* c277_stun.h - STUN codec for ICE-over-reflector (spec sec. 2.3; RFC 5389,
 * RFC 5245 attributes; libwebrtc port.cc/connection.cc). IPv4 only. */
#ifndef C277_STUN_H
#define C277_STUN_H

#include "c277_crypto.h"

#define C277_STUN_BIND_REQ  0x0001
#define C277_STUN_BIND_OK   0x0101
#define C277_STUN_BIND_ERR  0x0111

#define C277_STUN_COOKIE 0x2112A442UL

typedef struct {
    u32 type;
    u8  txid[12];
    const u8 *username; u32 username_len;   /* points into the datagram */
    int has_priority; u32 priority;
    int controlling, controlled; u8 tiebreak[8];
    int use_candidate;
    int has_mapped; u32 mapped_ip; u32 mapped_port;   /* host order, already un-XORed */
    int mi_off;     /* offset of the MESSAGE-INTEGRITY attribute header, -1 if absent */
    int fp_off;     /* offset of the FINGERPRINT attribute header, -1 if absent */
    int error_code; /* ERROR-CODE class*100+number, 0 if absent */
} c277_stun_msg;

/* STUN vs data demux on an unwrapped reflector payload (spec 2.3). */
int c277_stun_is_stun(const u8 *d, u32 n);

/* Parse header + attributes (unknown ones are skipped). 0 / -1. Does not verify hashes. */
int c277_stun_parse(const u8 *d, u32 n, c277_stun_msg *m);

/* 1 if FINGERPRINT is present, last, and valid. */
int c277_stun_check_fingerprint(const u8 *d, u32 n, const c277_stun_msg *m);

/* 1 if MESSAGE-INTEGRITY is present and equals HMAC-SHA1(key) over the message up
 * to the attribute with the header length rewritten to end right after MI. */
int c277_stun_check_integrity(const u8 *d, u32 n, const c277_stun_msg *m,
                              const u8 *key, u32 keylen);

/* Binding request: [SOFTWARE]? USERNAME PRIORITY (ICE-CONTROLLING|ICE-CONTROLLED)
 * [USE-CANDIDATE] MESSAGE-INTEGRITY(key) FINGERPRINT. username = "<peerUfrag>:<ourUfrag>",
 * key = peer pwd. Returns length or -1. */
int c277_stun_build_request(u8 *out, u32 cap, const u8 *txid12,
                            const u8 *username, u32 username_len, u32 priority,
                            int controlling, const u8 *tiebreak8, int use_candidate,
                            const u8 *key, u32 keylen);

/* Binding success response: [SOFTWARE]? XOR-MAPPED-ADDRESS MI(key = our pwd) FINGERPRINT. */
int c277_stun_build_success(u8 *out, u32 cap, const u8 *txid12, const char *software,
                            u32 ip_host, u32 port, const u8 *key, u32 keylen);

#endif
