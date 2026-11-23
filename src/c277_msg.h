/* c277_msg.h - EncryptedConnection message codec + SDP candidate line
 * (spec sec. 2.3, 3, 5). All integers big-endian. C89, caller buffers. */
#ifndef C277_MSG_H
#define C277_MSG_H

#include "c277_crypto.h"

#define C277_MSG_CANDIDATES   1
#define C277_MSG_VIDEOFORMATS 2
#define C277_MSG_REQUESTVIDEO 3
#define C277_MSG_MEDIASTATE   4
#define C277_MSG_AUDIO        5
#define C277_MSG_VIDEO        6
#define C277_MSG_UNSTRUCT     7
#define C277_MSG_VIDEOPARAMS  8
#define C277_MSG_BATTERY      9
#define C277_MSG_NETSTATUS    10
#define C277_MSG_EMPTY        0xFE
#define C277_MSG_ACK          0xFF

#define C277_MAX_CANDS 8

typedef struct { const u8 *p; u32 len; } c277_slice;

typedef struct {
    u32 n;                           /* candidates present in the message (may exceed C277_MAX_CANDS) */
    c277_slice cand[C277_MAX_CANDS]; /* first min(n, MAX) candidate strings */
    c277_slice ufrag, pwd;
} c277_cands;

/* Whether type is framed as "u16 len + data" (or rest-of-packet when single). */
int c277_msg_is_data(int type);

/* Size in bytes of the body of a non-data message of `type` starting at p, or
 * -1 if truncated/unknown type. Data types (5,6,7) -> -1 here; see below. */
int c277_msg_body_size(int type, const u8 *p, u32 avail);

/* Body bytes consumed by an entry of any known type: data types use u16 len
 * framing (single != 0: the rest of the packet, no prefix). *payload_off gets
 * the offset of the real payload inside the body (2 for framed data, else 0),
 * *payload_len its length. Returns consumed bytes or -1. */
int c277_msg_entry_body(int type, const u8 *p, u32 avail, int single,
                        u32 *payload_off, u32 *payload_len);

/* Data framing (types 5,6,7 in a multi-entry packet): u16 len | data. */
int c277_msg_wrap_data(const u8 *data, u32 n, u8 *out, u32 cap);

/* CandidatesList (id 1) body: u8 n; n*str; str ufrag; str pwd. */
int c277_msg_build_candidates(u8 *out, u32 cap, const c277_slice *cands, u32 n,
                              const c277_slice *ufrag, const c277_slice *pwd);
int c277_msg_parse_candidates(const u8 *body, u32 len, c277_cands *out);

/* RemoteMediaState (id 4): u8 (video<<1)|audio. audio 0 muted/1 active. */
u8   c277_msg_media_state_build(int audio, int video);
void c277_msg_media_state_parse(u8 b, int *audio, int *video);

/* SDP candidate line (sent in CandidatesList):
 * candidate:<foundation> 0 udp <priority> reflector-<id>-<tag>.reflector <port>
 *   typ relay generation 0 ufrag <ufrag> network-id 1 network-cost 10  (component 0, no raddr: as in the real capture)
 * Returns length (no NUL) or -1 if cap too small. */
int c277_sdp_cand_build(char *out, u32 cap, u32 foundation, u32 priority, u32 id, u32 tag,
                        u32 port, const char *ufrag);

typedef struct {
    u32 foundation_len;  /* unused detail kept minimal */
    u32 priority;
    u32 id;              /* reflector id from the hostname */
    u32 tag;             /* randomTag from the hostname (decimal) */
    u32 port;
} c277_sdp_cand;

/* Tolerant parse: token 0 "candidate:*" (optional "a=" prefix), token 1 component
 * "1", token 2 "udp", token 3 priority, token 4 hostname reflector-<id>-<tag>.reflector,
 * token 5 port, then "typ relay" somewhere after. 0 on success, -1 if the line is
 * not a reflector relay candidate. */
int c277_sdp_cand_parse(const char *s, u32 len, c277_sdp_cand *out);

/* Decimal helper shared with c277_refl: writes "<n>" at out, returns chars. */
u32 c277_put_dec(char *out, u32 n);

#endif
