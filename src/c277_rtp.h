/* c277_rtp.h - RTP packetizer/depacketizer and a small jitter buffer for the
 * AudioData message (spec sec. 4). C89, fixed arrays, no malloc. */
#ifndef C277_RTP_H
#define C277_RTP_H

#include "c277_crypto.h"

#define C277_RTP_PT        111
#define C277_RTP_SSRC_CALLER 2UL
#define C277_RTP_SSRC_CALLEE 1UL

/* Duration of an Opus packet in samples at 48 kHz from its TOC (RFC 6716 sec. 3),
 * 0 if malformed. 60 ms -> 2880. */
u32 c277_opus_samples48k(const u8 *p, u32 n);

/* ---- sender */
typedef struct { u32 ssrc, ts; u16 seq; } c277_rtp_tx;

/* rnd6: random initial sequence (2 bytes) and timestamp (4 bytes). is_outgoing: we are the caller. */
void c277_rtp_tx_init(c277_rtp_tx *t, int is_outgoing, const u8 *rnd6);
/* 12 byte header + opus. Timestamp then advances by the packet's duration
 * (2880 if the TOC is unusable). Returns length or -1. */
int c277_rtp_tx_build(c277_rtp_tx *t, const u8 *opus, u32 n, u8 *out, u32 cap);

/* ---- parser */
typedef struct {
    int pt, marker;
    u16 seq;
    u32 ts, ssrc;
    const u8 *payload;
    u32 plen;
} c277_rtp_hdr;

/* Returns 0 or -1 (not RTP v2, truncated, bad padding/extension). CSRCs, padding
 * and a header extension (any profile: 0xBEDE one-byte, 0x100x two-byte, others;
 * all share the 16-bit length-in-words framing) are skipped. */
int c277_rtp_parse(const u8 *p, u32 n, c277_rtp_hdr *h);
/* RTCP (RFC 5761 demux: second byte 192..223) */
int c277_rtp_is_rtcp(const u8 *p, u32 n);

/* ---- jitter buffer: whole packets keyed by RTP sequence */
#define C277_JB_SLOTS 16          /* power of two; the depth bound */
#define C277_JB_MAXPKT 600        /* max opus payload stored (120 ms @ 32 kbps = 480) */
#define C277_JB_REORDER 2         /* later packets seen before a missing one is declared lost */

#define C277_JB_EMPTY  0          /* nothing to play yet (underrun or still waiting for a late packet) */
#define C277_JB_PACKET 1          /* *len bytes of Opus in out */
#define C277_JB_LOST   2          /* next packet is a gap: run PLC; sequence advanced */

typedef struct {
    u32 len;
    u32 ts;
    u16 seq;
    int used;
    u8  data[C277_JB_MAXPKT];
} c277_jb_slot;

typedef struct {
    c277_jb_slot slot[C277_JB_SLOTS];
    u16 next;           /* next sequence to deliver */
    int started;
    int count;          /* stored packets */
    u32 n_in, n_late, n_dup, n_overflow, n_lost, n_big;
} c277_jb;

void c277_jb_init(c277_jb *jb);
/* 0 stored, 1 dropped (late/duplicate/too big). */
int c277_jb_put(c277_jb *jb, u16 seq, u32 ts, const u8 *data, u32 n);
/* status above; ts_out (may be NULL) gets the RTP timestamp of a delivered packet. */
int c277_jb_get(c277_jb *jb, u8 *out, u32 cap, u32 *len, u32 *ts_out);
int c277_jb_depth(const c277_jb *jb);

#endif
