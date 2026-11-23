/* c277_session.h - call orchestrator for the "2.7.7" voice path: ties the
 * transport + signalling EncryptedConnections, the reflector framing, the ICE
 * agent and RTP/jitter together. No sockets, no clock, no threads: the native
 * helper feeds datagrams/signalling payloads with a `now` in ms (wrap-safe u32)
 * and drains the output queue. C89, no malloc; the caller owns the struct
 * (about 60 KB: allocate it on the heap, not the Symbian stack). */
#ifndef C277_SESSION_H
#define C277_SESSION_H

#include "c277_conn.h"
#include "c277_refl.h"
#include "c277_ice.h"
#include "c277_rtp.h"
#include "c277_video.h"

#define C277_SESS_RANDOM  56    /* random bytes required by init */
#define C277_OUT_MAX      1500  /* bytes per output item */
#define C277_OUTQ         16    /* output queue capacity */
#define C277_CAP_MAX      8192  /* capture text ring bytes */
#define C277_SIG_RX_MAX   8192  /* largest accepted signalling payload */

#define C277_OUT_UDP     1      /* datagram to send to ip:port (reflector framing already applied) */
#define C277_OUT_SIGNAL  2      /* blob for phone.sendSignalingData (an EncryptedConnection packet) */

#define C277_SESS_OK        0
#define C277_SESS_ERR_ARG  (-20)   /* init: no usable (non-tcp phoneConnection) entry or too few random bytes */
#define C277_SESS_ERR_BUSY (-21)   /* output queue full / path not up: retry later */
#define C277_SESS_ERR_BIG  (-22)   /* payload too large */

typedef struct {
    int kind;
    u32 ip, port;          /* UDP only (host order) */
    u32 len;
    u8  data[C277_OUT_MAX];
} c277_out_item;

typedef struct {
    int n;                 /* items queued; the consumer sets n = 0 after draining */
    c277_out_item item[C277_OUTQ];
} c277_outq;

/* One server-provided connection. webrtc != 0 for phoneConnectionWebrtc (ignored,
 * excluded from the id ranking). tcp != 0: not used but kept in the ranking. */
typedef struct {
    c277_id64 id;          /* signed 64-bit phoneConnection.id split as hi (signed) / lo */
    u32 ip, port;          /* host order */
    u8  peer_tag[16];
    int tcp, webrtc;
} c277_sess_conn;

typedef struct {
    c277_conn sig, tr;
    c277_ice ice;
    c277_rtp_tx rtp;
    c277_jb jb;
    int is_outgoing, ok;
    /* the one reflector path */
    u32 r_ip, r_port, rank, own_rt;
    u8  tag16[16];
    int refl_ready, hello_started;
    u32 next_hello;
    int cands_sent, media_state_sent;
    /* peer */
    int peer_audio, peer_cands;
    int audio_seen;
    u32 cur_now;
    u32 last_audio_rx;
    u32 n_rtp_rx, n_rtp_tx, n_stun_rx;
    c277_outq out;
    u8 tmp[C277_OUT_MAX], rtpb[C277_OUT_MAX];
    u8 scratch[C277_SIG_RX_MAX];
    /* Stage 0 video capture (docs/CALL-VIDEO-SPEC.md): text log ring drained by the
     * helper, and the optional video reply. Both are off unless the helper sets
     * them (flag file E:\\retrotele_videocap.flag). Never logs keys or peer IPs. */
    int cap_on, vid_on;
    u32 cap_len, cap_drop;
    char cap[C277_CAP_MAX];
    int vf_reply, vf_sent, ms_resend;
    u32 vn_audio, vn_vid, vn_rtcp;                 /* totals */
    u32 vs_start, vs_pk, vs_bytes, vs_rtcp;        /* per-second window */
    int vs_npt, vs_nssrc;
    u32 vs_pt[4], vs_ssrc[4];
    /* Video send (docs/CALL-VIDEO-SPEC.md). vid_want: the user turned video on;
     * vid_act: we announced RemoteMediaState video=Active. */
    int vid_want, vid_act, vf_pending;
    u32 vf_at;                                   /* when our VideoFormats went out */
    int peer_vid;                                /* peer RemoteMediaState video (-1 unknown) */
    u32 req_video_n;                             /* RequestVideo messages from the peer */
    c277_vtx vtx;
    int sr_started;
    u32 sr_next, wall_unix, wall_now;
    u32 pli_n, fir_n, nack_n, twcc_n, remb_n, rtcp_rx;
    u32 rr_fraction, rr_lost, rr_jitter;
    int rr_have;
    int idr_req;                                 /* tgvideo.exe should produce an IDR */
    u32 idr_t0, last_pli_at;
    int idr_step;
    u32 vw_start, vw_au, vw_pk, vw_oct, vw_idr, vw_drop;   /* 1 s send window */
    u32 vtx_last_fps, vtx_last_bps;              /* last window result (fps x10, bit/s) */
    u32 peer_sps_t, n_sps_log;
    u8  peer_sps[24];
    u32 peer_sps_len;
    u32 n_peer_vrtp;
    /* Video receive (peer's picture). rx_want: reply with our VideoFormats so the peer sends
     * video, depacketize and ask for pictures; rx_fwd: the display helper is up and takes units. */
    int rx_want, rx_fwd;
    c277_vrx vrx;
    c277_sps rx_sps;                             /* parsed from the peer's newest SPS */
    int rx_sps_new;                              /* rx_sps changed: tell the display helper */
    int rx_pli_due;                              /* send a PLI at the next chance */
    u32 rx_pli_at, rx_rr_next, rx_remb_bps;
    u32 rx_pli_sent, rx_rr_sent, rx_nack_rtx, rx_ready_n, rx_nofwd, rx_nack_sent, rx_nack_at;
    /* the last 64 video packets for NACK retransmission */
    struct { u16 seq, len; u8 d[1040]; } vhist[64];
} c277_session;

/* key256: raw DH key. rnd: C277_SESS_RANDOM random bytes (nrnd = how many).
 * Returns C277_SESS_OK or C277_SESS_ERR_ARG. */
int c277_session_init(c277_session *s, const u8 *key256, int is_outgoing,
                      const c277_sess_conn *conns, u32 nconns, const u8 *rnd, u32 nrnd);

/* A datagram that arrived from ip:port (anything not from our reflector is ignored). */
void c277_session_on_udp(c277_session *s, u32 ip, u32 port, const u8 *d, u32 n, u32 now);

/* Payload of updatePhoneCallSignalingData. Returns 0 or a C277_ERR_* from c277_conn. */
int c277_session_on_signaling(c277_session *s, const u8 *d, u32 n, u32 now);

/* Run timers; appends due items to s->out. Call every <= 20 ms. Returns s->out.n. */
int c277_session_tick(c277_session *s, u32 now);

/* Send one Opus packet (any valid TOC; the RTP timestamp advances by its duration).
 * C277_SESS_ERR_BUSY until ICE is connected or if the output queue is full. */
int c277_session_send_opus(c277_session *s, const u8 *opus, u32 n, u32 now);

/* Next received Opus packet in sequence order: C277_JB_PACKET (out/len valid),
 * C277_JB_LOST (run PLC for one packet), C277_JB_EMPTY. */
int c277_session_poll_opus(c277_session *s, u8 *out, u32 cap, u32 *len);

void c277_outq_clear(c277_outq *q);

/* Capture: on != 0 logs every decrypted message; vid != 0 also answers the peer's
 * VideoFormats with ours (H264 only) and RemoteMediaState video=0. */
void c277_session_capture(c277_session *s, int on, int vid);
/* Copies up to cap bytes of pending capture text into out and removes them. */
u32  c277_session_cap_take(c277_session *s, char *out, u32 cap);

/* ---- video receive */
/* want: answer the peer's video offer and depacketize its video; fwd: the display helper takes
 * access units (turning it on asks the peer for an IDR). remb_kbps: bitrate the peer is told it
 * may send (0 = no REMB). */
void c277_session_rx_enable(c277_session *s, int want, int fwd, u32 remb_kbps);
/* A complete access unit (Annex-B, parameter sets before an IDR) if one is ready: 1 and the
 * pointer/length/idr flag, else 0. Call c277_session_vrx_done afterwards. */
int  c277_session_vrx_take(c277_session *s, const u8 **au, u32 *len, int *idr);
void c277_session_vrx_done(c277_session *s);
/* New peer SPS since the last call: 1 and the parsed size/profile/level. */
int  c277_session_vrx_sps_take(c277_session *s, c277_sps *o);

/* ---- video send. A helper (tgvideo.exe via the call engine) feeds encoder units. */
/* 0 = off, 1 = on. Turning on announces VideoFormats / VideoParameters / RemoteMediaState
 * (video Active) as soon as the path is up; off announces video Inactive. */
void c277_session_video_enable(c277_session *s, int on);
/* One encoder unit (Annex-B). C277_VTX_* result (DROPPED also while not active). */
int  c277_session_video_put(c277_session *s, const u8 *unit, u32 n, u32 now);
/* Emits packets of the queued access unit while the output queue has room; returns 1
 * while more remain (drain s->out, then call again). */
int  c277_session_video_pump(c277_session *s, u32 now);
/* Wall clock for RTCP sender reports: unix seconds at time now (ms). */
void c277_session_set_wall(c277_session *s, u32 unix_sec, u32 now);
/* 1 once if an IDR should be requested from the encoder (PLI/FIR, or the early schedule). */
int  c277_session_take_idr_req(c277_session *s);
/* Video state */
int  c277_session_video_active(const c277_session *s);

/* state */
int c277_session_signaling_acked(const c277_session *s);  /* our CandidatesList sent and acked */
int c277_session_refl_ready(const c277_session *s);
int c277_session_ice_connected(const c277_session *s);
int c277_session_ice_state(const c277_session *s);        /* C277_ICE_* */
int c277_session_media_flowing(const c277_session *s, u32 now);  /* RTP received within 2 s */
int c277_session_peer_audio_active(const c277_session *s); /* peer's RemoteMediaState says audio on */

#endif
