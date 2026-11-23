/* c277_video.h - video helpers for the "2.7.7" call (docs/CALL-VIDEO-SPEC.md):
 *  - H.264 Annex-B splitting and SPS decoding (profile, level, width x height)
 *  - RFC 6184 packetizer (packetization-mode 1: single NAL, STAP-A, FU-A) that
 *    emits complete RTP packets with the transport-cc one-byte header extension
 *  - RTCP: sender report (+ SDES CNAME) builder, parser for PLI / FIR / NACK / RR
 * C89, fixed arrays, no malloc, no writable static data. */
#ifndef C277_VIDEO_H
#define C277_VIDEO_H

#include "c277_crypto.h"

#define C277_VPT          96        /* the one H264 format we offer -> first dynamic payload type */
#define C277_VMTU         1000      /* max RTP payload bytes per packet */
#define C277_VAU_MAX      16384     /* largest access unit accepted */
#define C277_VNAL_MAX     24
#define C277_VPS_MAX      128       /* cached SPS / PPS size */
#define C277_VEXT_ID      2         /* transport-wide-cc one-byte header extension id (video) */

typedef struct { u32 off, len; } c277_nal;

/* Splits Annex-B data (00 00 01 / 00 00 00 01 start codes) into NAL units (offset,
 * length without start code and trailing zero bytes). Data without any start code
 * is one NAL. Returns the count (at most max). */
int c277_annexb_split(const u8 *d, u32 n, c277_nal *out, u32 max);

typedef struct { int ok, profile, constraints, level, width, height; } c277_sps;
/* nal: the SPS NAL including its header byte. Returns 0 on success. */
int c277_sps_parse(const u8 *nal, u32 n, c277_sps *o);

/* ---- sender */
typedef struct {
    u32 ssrc, ts_base, t0;
    u16 seq, tseq;
    int started;               /* t0 set */
    int sent_idr;              /* an IDR access unit has been queued: P frames may follow */
    /* the access unit being sent */
    u8  au[C277_VAU_MAX];
    c277_nal nal[C277_VNAL_MAX];
    int n_nal, pending, idr, it_nal, it_stap;
    u32 it_off, au_ts;
    u8  sps[C277_VPS_MAX], pps[C277_VPS_MAX];
    u32 sps_len, pps_len;
    /* totals */
    u32 n_pk, n_oct, n_au, n_idr, n_drop, n_drop_idr, n_params;
} c277_vtx;

#define C277_VTX_QUEUED  0     /* access unit queued: call c277_vtx_next until it returns 0 */
#define C277_VTX_PARAMS  1     /* only parameter sets / nothing to send: cached */
#define C277_VTX_DROPPED 2     /* dropped (busy, no IDR yet, no parameter sets) */

/* rnd6: initial sequence (2), timestamp base (4). */
void c277_vtx_init(c277_vtx *v, u32 ssrc, const u8 *rnd6);
/* One encoder output unit (Annex-B, may hold several NALs). The RTP timestamp is
 * 90 kHz derived from now (ms), continuous across encoder restarts. */
int  c277_vtx_put(c277_vtx *v, const u8 *unit, u32 n, u32 now);
/* Next complete RTP packet of the queued access unit (header + extension + payload,
 * marker on the last); returns its length or 0 when the unit is done. */
int  c277_vtx_next(c277_vtx *v, u8 *out, u32 cap);
/* Forget the queued unit and require a new IDR (video turned off). */
void c277_vtx_reset(c277_vtx *v);
/* RTP timestamp that corresponds to now (for sender reports). */
u32  c277_vtx_ts_at(const c277_vtx *v, u32 now);

/* ---- RTCP */
/* SR (28 bytes, no report blocks) + SDES with CNAME "cname" (16): 44 bytes. */
int c277_rtcp_build_sr(u8 *out, u32 cap, u32 ssrc, u32 ntp_hi, u32 ntp_lo, u32 rtp_ts, u32 pk, u32 oct);

#define C277_NACK_SEQ_MAX 16
typedef struct {
    u32 n_sr, n_rr, n_pli, n_fir, n_nack, n_twcc, n_remb, n_other;
    u16 nack_seq[C277_NACK_SEQ_MAX];       /* sequence numbers asked for (about our ssrc) */
    u32 n_nack_seq;
    int rr_have;                          /* a report block for our ssrc was present */
    u32 rr_fraction, rr_lost, rr_jitter;
} c277_rtcp_info;

/* Walks a compound RTCP packet; only PLI/FIR/NACK/RR blocks about our_ssrc (or any
 * ssrc for PLI/FIR when our_ssrc == 0) are counted. Returns 0 or -1 if malformed. */
int c277_rtcp_parse(const u8 *p, u32 n, u32 our_ssrc, c277_rtcp_info *o);
/* PLI (RFC 4585, 12 bytes) for tests. */
int c277_rtcp_build_pli(u8 *out, u32 cap, u32 sender, u32 media);


/* RR with one report block (32 bytes) about media_ssrc, REMB (24 bytes) */
int c277_rtcp_build_rr(u8 *out, u32 cap, u32 sender, u32 media, u32 fraction, u32 cum_lost,
                       u32 ext_hi_seq, u32 jitter);
int c277_rtcp_build_remb(u8 *out, u32 cap, u32 sender, u32 media, u32 bitrate_bps);

/* ---- receiver (peer's video): RFC 6184 depacketizer -> Annex-B access units.
 * Packets must arrive in order; a gap or a damaged access unit discards the picture
 * and the stream waits for the next IDR (PLI requested). */
#define C277_VRX_AU_MAX  32768
#define C277_VRX_SLOTS   16       /* reorder buffer depth */
#define C277_VRX_PKT_MAX 1100
#define C277_VRX_NACK_MAX 8
#define C277_VRX_GAP_MS  80       /* wait this long (or for 8 later packets) before a gap is declared lost */
typedef struct {
    int started, in_au, need_idr, ready, ready_idr, need_pli, au_ok, fu_open, au_idr, au_sps, au_pps;
    u32 ssrc, au_ts, au_len, ready_len, ready_ts;
    u16 next_seq;
    u8  au[C277_VRX_AU_MAX];
    u8  sps[C277_VPS_MAX], pps[C277_VPS_MAX];
    u32 sps_len, pps_len;
    int sps_changed;                       /* new SPS content since the last c277_vrx_sps_take */
    /* RR statistics */
    u32 base_seq, max_ext, received, expected_prior, received_prior;
    /* reorder buffer: packets that arrived ahead of a gap wait here */
    struct { u16 seq, len; u32 ts; u8 used, marker; u8 d[C277_VRX_PKT_MAX]; } slot[C277_VRX_SLOTS];
    int nbuf;
    u32 gap_t;                             /* when the current gap was first seen (0 = none) */
    u16 nack[C277_VRX_NACK_MAX];           /* missing sequence numbers worth a NACK */
    u32 n_nack, n_reordered, n_gap_timeout, n_big;
    /* totals */
    u32 n_pk, n_au, n_idr, n_lost, n_drop_au, n_late, n_wait;
} c277_vrx;

void c277_vrx_init(c277_vrx *v);
/* Feeds one RTP packet (video PT). Returns 1 when an access unit is ready in v->au
 * (v->ready_len bytes, v->ready_idr), else 0. v->need_pli says a picture request is due. */
int  c277_vrx_put(c277_vrx *v, u16 seq, u32 ts, int marker, u32 ssrc, const u8 *payload, u32 plen, u32 now);
/* Timer: declares an old gap lost. Returns 1 if an access unit became ready. */
int  c277_vrx_tick(c277_vrx *v, u32 now);
/* NACK (RTPFB fmt 1) for one pid + bitmask */
int c277_rtcp_build_nack(u8 *out, u32 cap, u32 sender, u32 media, u32 pid, u32 blp);
/* The consumer took the ready unit (buffered packets are processed; check ready again). */
void c277_vrx_done(c277_vrx *v);
/* Report block data for an RR: fraction lost since the last call (0..255), cumulative lost, extended highest seq */
void c277_vrx_stats(c277_vrx *v, u32 *fraction, u32 *cum_lost, u32 *ext_hi);

#endif
