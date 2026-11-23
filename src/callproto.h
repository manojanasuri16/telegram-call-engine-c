/* callproto.h - media layer core of Telegram's legacy voice-call protocol
 * (libtgvoip "2.4.4", short format, MTProto2 crypto, UDP relay, Opus 60 ms).
 * Spec: retrotele/docs/CALL-PROTOCOL.md; libtgvoip refs are to
 * VoIPController.cpp on the `public` branch (grishka/libtgvoip).
 *
 * Portable C89 (GCC 3.4.3 / Symbian): caller-provided buffers, no sockets,
 * no Opus, no malloc, no writable statics, no floating point.
 * Everything is little-endian on the wire. The ctx is ~2.1 KB: allocate it
 * on the heap or as a member, not on a small Symbian stack. */
#ifndef CALLPROTO_H
#define CALLPROTO_H

#include "callproto_crypto.h"

/* packet types (PrivateDefines.h:9-24) */
#define TGCP_PKT_INIT          1
#define TGCP_PKT_INIT_ACK      2
#define TGCP_PKT_STREAM_DATA   4
#define TGCP_PKT_PING          6
#define TGCP_PKT_PONG          7
#define TGCP_PKT_STREAM_X2     8
#define TGCP_PKT_STREAM_X3     9
#define TGCP_PKT_NOP          14

#define TGCP_PROTO_VERSION     9
#define TGCP_MIN_PROTO_VERSION 3
#define TGCP_CODEC_OPUS        0x4F505553UL   /* wire bytes 53 55 50 4F */
#define TGCP_FRAME_MS          60

#define TGCP_MAX_PAYLOAD       1024
#define TGCP_MAX_DATAGRAM      1104   /* 16+16+2+14+1024+31 rounded */
#define TGCP_MAX_INCOMING      1500   /* libtgvoip decrypt buffer (:2000) */

/* return codes (<0 errors, >0 non-error "ignored") */
#define TGCP_OK          0
#define TGCP_DUP         1    /* duplicate / too old: ignored, acks untouched */
#define TGCP_REFLECTOR   2    /* unencrypted relay TL packet: not parsed here */
#define TGCP_E_SHORT    (-1)
#define TGCP_E_TAG      (-2)
#define TGCP_E_ALIGN    (-3)  /* ciphertext not multiple of 16 / too big */
#define TGCP_E_MSGKEY   (-4)
#define TGCP_E_INNER    (-5)  /* bad inner length / too little padding */
#define TGCP_E_HEADER   (-6)
#define TGCP_E_CAP      (-7)  /* output buffer too small */
#define TGCP_E_ARG      (-8)
#define TGCP_E_PROTO    (-9)  /* peer version incompatible */
#define TGCP_E_STATE   (-10)

/* connection state */
#define TGCP_ST_INIT_SENT  1
#define TGCP_ST_CONNECTED  2
#define TGCP_ST_FAILED     3

/* timing (spec sec. 4) */
#define TGCP_INIT_RETRY_MS     500
#define TGCP_INIT_TIMEOUT_MS   30000  /* no INIT_ACK -> FAILED (initTimeout) */
#define TGCP_RECONNECT_MS      2000   /* no rx -> tgcp_is_reconnecting() */
#define TGCP_RECV_TIMEOUT_MS   20000  /* no rx while CONNECTED -> FAILED */
#define TGCP_PING_MS           10000
#define TGCP_NOP_THRESHOLD     10     /* NOP when > 10 rx packets unacked */

/* fills n random bytes; used for padding only (not security critical) */
typedef void (*tgcp_pad_fn)(void *user, u8 *buf, u32 n);

typedef struct tgcp_ctx {
    u8  key[256];
    u8  peer_tag[16];
    int is_outgoing;
    int state;
    int fail_reason;           /* TGCP_E_* that caused FAILED, 0 = timeout */
    /* tx */
    u32 out_seq;               /* next seq to use, starts at 1 */
    u32 s_seq[64];             /* ring of recent sent seqs, slot = seq & 63 */
    u8  s_pend[64];            /* 1 = sent and not yet acked */
    u32 unacked_out;
    u32 lost_out;              /* sent packets that fell out of the ack mask */
    u32 last_ack_seq;          /* highest ack_seq seen from peer */
    u32 pts_out;
    u32 unack_in;              /* received since our last transmit */
    /* rx */
    int have_rx;
    u32 last_remote_seq;
    u32 rw[4];                 /* bit i = seq (last_remote_seq - i) received */
    u32 last_rx_seq;           /* seq of the last packet parsed OK */
    /* handshake */
    int got_init, got_init_ack;
    u32 peer_proto, peer_min_proto;
    u8  peer_audio_stream;
    int pend_init_ack, pend_pong;
    u32 pong_seq;
    /* timers (ms, wrap-safe) */
    u32 now, start_ms, last_rx_ms, last_tx_ms, last_init_ms, last_ping_ms;
    int started, init_sent_once;
    /* padding */
    tgcp_pad_fn pad_fn;
    void *pad_user;
    u32 prng;
    /* decrypt scratch (avoids big stack use) */
    u8  scratch[TGCP_MAX_INCOMING + 16];
} tgcp_ctx;

typedef struct {
    u32 proto, min_proto;
    int n_streams;
    u8  audio_stream_id;   /* first enabled audio stream, 0 if none */
    u32 audio_codec;
    u16 frame_ms;          /* as claimed by sender; receiver hard-codes 60 */
} tgcp_init_ack_info;

/* ---- session ---- */
/* auth_key: 256 raw bytes (used as is, no hashing). peer_tag: relay tag. */
void tgcp_init(tgcp_ctx *c, const u8 *auth_key, int is_outgoing, const u8 *peer_tag);
void tgcp_set_peer_tag(tgcp_ctx *c, const u8 *peer_tag);       /* switch relay */
void tgcp_set_pad_source(tgcp_ctx *c, tgcp_pad_fn fn, void *user); /* test hook */
void tgcp_set_now(tgcp_ctx *c, u32 now_ms);   /* optional; tick does it too */
/* rewrite the tag of an already built datagram (send same INIT to N relays) */
void tgcp_retag(u8 *datagram, const u8 *peer_tag);

/* ---- datagram layer ---- */
/* Builds peer_tag||msg_key||IGE(u16 len||header||payload||pad). Returns the
 * datagram length (>0) or <0. Uses a new seq, current ack state; resets the
 * "rx unacked" counter. */
int tgcp_build_datagram(tgcp_ctx *c, u8 type, const u8 *payload, u32 len,
                        u8 *out, u32 out_cap);
/* Decrypts/validates. On entry *payload_len = capacity of payload_out, on
 * success = payload length (extras/recv_ts skipped). Returns TGCP_OK,
 * TGCP_DUP, TGCP_REFLECTOR or a TGCP_E_*. Also drives the handshake:
 * INIT -> queue INIT_ACK, INIT_ACK -> CONNECTED, PING -> queue PONG. */
int tgcp_parse_datagram(tgcp_ctx *c, const u8 *in, u32 len, u8 *type,
                        u8 *payload_out, u32 *payload_len);

/* ---- payload helpers (return payload length, or <0) ---- */
int tgcp_make_init(u8 *out, u32 cap);                       /* 19 bytes */
int tgcp_make_init_ack(u8 *out, u32 cap);                   /* 18 bytes */
int tgcp_parse_init(const u8 *p, u32 len, u32 *proto, u32 *min_proto);
int tgcp_parse_init_ack(const u8 *p, u32 len, tgcp_init_ack_info *info);
int tgcp_make_stream_data(const u8 *opus, u32 len, u32 pts, u8 *out, u32 cap);
/* Parses ONE frame; returns bytes consumed (>0) so the caller can loop for
 * STREAM_X2/X3, or <0. *opus points into p. EXTRA_FEC trailer is skipped. */
int tgcp_parse_stream_data(const u8 *p, u32 len, u8 *stream_id, u32 *pts,
                           const u8 **opus, u32 *opus_len);
int tgcp_make_ping(u8 *out, u32 cap);                       /* 0 bytes */
int tgcp_make_pong(u32 ping_seq, u8 *out, u32 cap);         /* 4 bytes */
int tgcp_make_nop(u8 *out, u32 cap);                        /* 0 bytes */

/* convenience: build a STREAM_DATA datagram, pts auto += 60. Needs CONNECTED. */
int tgcp_send_audio(tgcp_ctx *c, const u8 *opus, u32 len, u8 *out, u32 cap);

/* ---- relay (reflector) packets, unencrypted ---- */
/* 40 bytes (spec says 44; 16+4*4+8 = 40, matches SendUdpPing :3326): tag||-1||-1||-1||-2||id[8] */
int tgcp_make_reflector_ping(const u8 *peer_tag, const u8 *query_id8, u8 *out, u32 cap);
/* 1 = UDP_REFLECTOR_SELF_INFO reply (query_id8 filled if non-NULL),
 * 2 = other reflector TL packet, 0 = not a reflector packet. */
int tgcp_is_reflector_reply(const u8 *in, u32 len, u8 *query_id8);

/* ---- timing ---- */
/* Call every ~20 ms (and after rx). Builds at most one datagram per call;
 * call again while it returns >0. Order: INIT_ACK, PONG, INIT (500 ms until
 * INIT_ACK), NOP (>10 unacked rx), PING (10 s). Returns bytes, 0 = nothing,
 * <0 = error. Also evaluates the timeouts. */
int tgcp_tick(tgcp_ctx *c, u32 now_ms, u8 *out, u32 out_cap);

int  tgcp_get_state(const tgcp_ctx *c);
int  tgcp_is_reconnecting(const tgcp_ctx *c);   /* CONNECTED, no rx for 2 s */
u32  tgcp_unacked_out(const tgcp_ctx *c);
u32  tgcp_last_rx_seq(const tgcp_ctx *c);
int  tgcp_got_init(const tgcp_ctx *c);
int  tgcp_got_init_ack(const tgcp_ctx *c);

#endif
