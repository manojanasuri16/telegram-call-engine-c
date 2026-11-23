/* callproto.c - see callproto.h. C89; no malloc, no writable statics. */
#include <string.h>
#include "callproto.h"

#define HDR_LEN 14

/* ------------------------------------------------------------ LE helpers */
static void w16(u8 *p, u32 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static void w32(u8 *p, u32 v)
{
    p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}
static u32 r16(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8); }
static u32 r32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* seqgt: PrivateDefines.h:122 */
static int seqgt(u32 a, u32 b)
{
    return (a > b && (a - b) <= 0x7FFFFFFFUL) || (a < b && (b - a) > 0x7FFFFFFFUL);
}

/* ------------------------------------------------------------ crypto glue */

/* KDF2, VoIPController.cpp:3230. buf layout follows the source exactly. */
static void kdf2(const u8 *key, const u8 *msg_key, u32 x, u8 *aes_key, u8 *aes_iv)
{
    u8 sA[32], sB[32], buf[52];
    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, key + x, 36);
    tgc_sha256(buf, 52, sA);
    memcpy(buf, key + 40 + x, 36);
    memcpy(buf + 36, msg_key, 16);
    tgc_sha256(buf, 52, sB);
    memcpy(aes_key, sA, 8);       memcpy(aes_key + 8, sB + 8, 16);  memcpy(aes_key + 24, sA + 24, 8);
    memcpy(aes_iv, sB, 8);        memcpy(aes_iv + 8, sA + 8, 16);   memcpy(aes_iv + 24, sB + 24, 8);
}

/* msg_key = SHA256(key[88+x..+32) || inner)[8..24)  (:2958, :1997) */
static void calc_msg_key(const u8 *key, u32 x, const u8 *inner, u32 n, u8 *msg_key)
{
    tgc_sha256_ctx s;
    u8 big[32];
    tgc_sha256_init(&s);
    tgc_sha256_update(&s, key + 88 + x, 32);
    tgc_sha256_update(&s, inner, n);
    tgc_sha256_final(&s, big);
    memcpy(msg_key, big + 8, 16);
}

static void default_pad(void *user, u8 *buf, u32 n)
{
    tgcp_ctx *c = (tgcp_ctx *)user;
    u32 i, s = c->prng;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;   /* xorshift32 */
        buf[i] = (u8)(s >> 11);
    }
    c->prng = s;
}

/* ------------------------------------------------------------ session */

void tgcp_init(tgcp_ctx *c, const u8 *auth_key, int is_outgoing, const u8 *peer_tag)
{
    memset(c, 0, sizeof(*c));
    memcpy(c->key, auth_key, 256);
    memcpy(c->peer_tag, peer_tag, 16);
    c->is_outgoing = is_outgoing ? 1 : 0;
    c->state = TGCP_ST_INIT_SENT;
    c->out_seq = 1;
    c->prng = r32(auth_key + 200) ^ (r32(peer_tag) * 2654435761UL) ^ (is_outgoing ? 0x9E3779B9UL : 0x7F4A7C15UL);
    if (c->prng == 0) c->prng = 1;
    c->pad_fn = default_pad;
    c->pad_user = c;
}

void tgcp_set_peer_tag(tgcp_ctx *c, const u8 *peer_tag) { memcpy(c->peer_tag, peer_tag, 16); }
void tgcp_set_now(tgcp_ctx *c, u32 now_ms)
{
    c->now = now_ms;
    if (!c->started) {
        c->started = 1;
        c->start_ms = c->last_rx_ms = c->last_tx_ms = c->last_ping_ms = now_ms;
    }
}
void tgcp_set_pad_source(tgcp_ctx *c, tgcp_pad_fn fn, void *user)
{
    if (fn) { c->pad_fn = fn; c->pad_user = user; }
    else { c->pad_fn = default_pad; c->pad_user = c; }
}
void tgcp_retag(u8 *datagram, const u8 *peer_tag) { memcpy(datagram, peer_tag, 16); }

/* ------------------------------------------------------------ rx window */

static void win_shift(u32 *w, u32 d)
{
    int i, src, ws, bs;
    if (d >= 128) { w[0] = w[1] = w[2] = w[3] = 0; return; }
    ws = (int)(d >> 5); bs = (int)(d & 31);
    for (i = 3; i >= 0; i--) {
        u32 v = 0;
        src = i - ws;
        if (src >= 0) {
            v = w[src] << bs;
            if (bs && src > 0) v |= w[src - 1] >> (32 - bs);
        }
        w[i] = v;
    }
}

/* returns 1 if new (and records it), 0 if duplicate / too old (:2128-2142) */
static int rx_record(tgcp_ctx *c, u32 seq)
{
    u32 d;
    if (!c->have_rx) {
        c->have_rx = 1; c->last_remote_seq = seq;
        c->rw[0] = 1; c->rw[1] = c->rw[2] = c->rw[3] = 0;
        return 1;
    }
    if (seq == c->last_remote_seq) return 0;
    if (seqgt(seq, c->last_remote_seq)) {
        d = seq - c->last_remote_seq;
        win_shift(c->rw, d);
        c->rw[0] |= 1;
        c->last_remote_seq = seq;
        return 1;
    }
    d = c->last_remote_seq - seq;
    if (d >= 128) return 0;
    if (c->rw[d >> 5] & (1UL << (d & 31))) return 0;
    c->rw[d >> 5] |= 1UL << (d & 31);
    return 1;
}

/* bit (31-i) <=> seq (last_remote_seq-(i+1)) received (:1391-1400) */
static u32 rx_ack_mask(const tgcp_ctx *c)
{
    u32 m = 0, i, b;
    for (i = 0; i < 32; i++) {
        b = i + 1;
        if (c->rw[b >> 5] & (1UL << (b & 31))) m |= 1UL << (31 - i);
    }
    return m;
}

/* peer's ack_seq/ack_mask acknowledge OUR packets (:2162-2185) */
static void tx_process_acks(tgcp_ctx *c, u32 ack_seq, u32 mask)
{
    int i;
    u32 d;
    if (ack_seq == 0) return;                       /* peer has received nothing */
    if (c->last_ack_seq != 0 && seqgt(c->last_ack_seq, ack_seq)) return; /* stale */
    c->last_ack_seq = ack_seq;
    for (i = 0; i < 64; i++) {
        if (!c->s_pend[i]) continue;
        d = ack_seq - c->s_seq[i];
        if (d == 0 || (d <= 32 && ((mask >> (32 - d)) & 1))) {
            c->s_pend[i] = 0; c->unacked_out--;
        } else if (d > 32 && d < 0x80000000UL) {    /* fell out of the mask: lost */
            c->s_pend[i] = 0; c->unacked_out--; c->lost_out++;
        }
    }
}

/* ------------------------------------------------------------ datagrams */

int tgcp_build_datagram(tgcp_ctx *c, u8 type, const u8 *payload, u32 len,
                        u8 *out, u32 out_cap)
{
    u32 plen, inner_nopad, pad, total, x, seq, slot;
    u8 *p, msg_key[16], ak[32], iv[32];

    if (len > TGCP_MAX_PAYLOAD || (len && !payload)) return TGCP_E_ARG;
    plen = HDR_LEN + len;
    inner_nopad = 2 + plen;
    pad = 16 - (inner_nopad % 16);          /* :2951 */
    if (pad < 16) pad += 16;
    total = 32 + inner_nopad + pad;
    if (out_cap < total) return TGCP_E_CAP;

    seq = c->out_seq++;
    memcpy(out, c->peer_tag, 16);
    p = out + 32;
    w16(p, plen);
    p[2] = type;
    w32(p + 3, c->have_rx ? c->last_remote_seq : 0);
    w32(p + 7, seq);
    w32(p + 11, rx_ack_mask(c));
    p[15] = 0;                              /* flags: no extras, no recv_ts */
    if (len) memcpy(p + 16, payload, len);
    c->pad_fn(c->pad_user, p + inner_nopad, pad);

    x = c->is_outgoing ? 0 : 8;
    calc_msg_key(c->key, x, p, inner_nopad + pad, msg_key);
    kdf2(c->key, msg_key, x, ak, iv);
    tgc_ige(p, p, (int)(inner_nopad + pad), ak, iv, 0);
    memcpy(out + 16, msg_key, 16);

    slot = seq & 63;
    if (!c->s_pend[slot]) c->unacked_out++;
    c->s_pend[slot] = 1; c->s_seq[slot] = seq;
    c->unack_in = 0;
    c->last_tx_ms = c->now;
    return (int)total;
}

int tgcp_parse_datagram(tgcp_ctx *c, const u8 *in, u32 len, u8 *type,
                        u8 *payload_out, u32 *payload_len)
{
    u32 clen, x, inner_len, ack_seq, seq, mask, off, i, n, plen, flags, el;
    const u8 *msg_key, *cipher, *pk;
    u8 ak[32], iv[32], chk[16], *d;

    if (len < 16) return TGCP_E_SHORT;
    if (memcmp(in, c->peer_tag, 16) != 0) return TGCP_E_TAG;
    if (len >= 28) {                       /* FF*12 marker, :1871 */
        for (i = 16; i < 28 && in[i] == 0xFF; i++) ;
        if (i == 28) return TGCP_REFLECTOR;
    }
    if (len - 16 < 40) return TGCP_E_SHORT;              /* :1930 */
    msg_key = in + 16;
    cipher = in + 32;
    clen = len - 32;
    if (clen > TGCP_MAX_INCOMING || (clen % 16) != 0) return TGCP_E_ALIGN;

    x = c->is_outgoing ? 8 : 0;
    kdf2(c->key, msg_key, x, ak, iv);
    d = c->scratch;
    tgc_ige(cipher, d, (int)clen, ak, iv, 1);
    calc_msg_key(c->key, x, d, clen, chk);
    if (memcmp(chk, msg_key, 16) != 0) return TGCP_E_MSGKEY;

    inner_len = r16(d);
    if (inner_len > clen - 2 || clen - inner_len < 16 || inner_len < HDR_LEN) return TGCP_E_INNER;
    pk = d + 2;                            /* plaintext packet P */

    *type = pk[0];
    ack_seq = r32(pk + 1);
    seq = r32(pk + 5);
    mask = r32(pk + 9);
    flags = pk[13];
    off = HDR_LEN;
    plen = inner_len;
    if (flags & 1) {                       /* extras, :2150 */
        if (off >= plen) return TGCP_E_HEADER;
        n = pk[off++];
        for (i = 0; i < n; i++) {
            if (off >= plen) return TGCP_E_HEADER;
            el = pk[off++];
            if (off + el > plen) return TGCP_E_HEADER;
            off += el;
        }
    }
    if (flags & 2) {                       /* recv_ts */
        if (off + 4 > plen) return TGCP_E_HEADER;
        off += 4;
    }
    n = plen - off;
    if (n > *payload_len) return TGCP_E_CAP;

    /* only now mutate state */
    if (!rx_record(c, seq)) return TGCP_DUP;
    c->last_rx_seq = seq;
    c->unack_in++;
    c->last_rx_ms = c->now;
    tx_process_acks(c, ack_seq, mask);
    if (n) memcpy(payload_out, pk + off, n);
    *payload_len = n;

    switch (*type) {
    case TGCP_PKT_INIT: {
        u32 v = 0, mv = 0;
        if (tgcp_parse_init(payload_out, n, &v, &mv) == 0) {
            c->peer_proto = v; c->peer_min_proto = mv;
            if (mv > TGCP_PROTO_VERSION || v < TGCP_MIN_PROTO_VERSION) { /* :2309 */
                c->state = TGCP_ST_FAILED; c->fail_reason = TGCP_E_PROTO;
                return TGCP_E_PROTO;
            }
            c->got_init = 1;
            c->pend_init_ack = 1;          /* answer EVERY INIT */
        }
        break; }
    case TGCP_PKT_INIT_ACK: {
        tgcp_init_ack_info ia;
        if (tgcp_parse_init_ack(payload_out, n, &ia) == 0 && ia.audio_stream_id) {
            c->got_init_ack = 1;
            c->peer_audio_stream = ia.audio_stream_id;
            if (c->state == TGCP_ST_INIT_SENT) {
                c->state = TGCP_ST_CONNECTED;
                c->last_ping_ms = c->now;
            }
        }
        break; }
    case TGCP_PKT_PING:
        c->pend_pong = 1; c->pong_seq = seq;
        break;
    default:
        break;
    }
    return TGCP_OK;
}

/* ------------------------------------------------------------ payloads */

int tgcp_make_init(u8 *out, u32 cap)
{
    if (cap < 19) return TGCP_E_CAP;
    w32(out, TGCP_PROTO_VERSION);
    w32(out + 4, TGCP_MIN_PROTO_VERSION);
    w32(out + 8, 0);                       /* flags */
    out[12] = 1;                           /* audio codec count */
    w32(out + 13, TGCP_CODEC_OPUS);
    out[17] = 0;                           /* video decoder count */
    out[18] = 0;                           /* max video resolution */
    return 19;
}

int tgcp_make_init_ack(u8 *out, u32 cap)
{
    if (cap < 18) return TGCP_E_CAP;
    w32(out, TGCP_PROTO_VERSION);
    w32(out + 4, TGCP_MIN_PROTO_VERSION);
    out[8] = 1;                            /* stream count */
    out[9] = 1;                            /* stream id */
    out[10] = 1;                           /* STREAM_TYPE_AUDIO */
    w32(out + 11, TGCP_CODEC_OPUS);
    w16(out + 15, TGCP_FRAME_MS);
    out[17] = 1;                           /* enabled */
    return 18;
}

int tgcp_parse_init(const u8 *p, u32 len, u32 *proto, u32 *min_proto)
{
    if (len < 8) return -1;
    *proto = r32(p); *min_proto = r32(p + 4);
    return 0;
}

/* :2410-2425; frame duration is read and discarded (peer assumes 60 ms) */
int tgcp_parse_init_ack(const u8 *p, u32 len, tgcp_init_ack_info *info)
{
    u32 off, i, n;
    if (len < 9) return -1;
    memset(info, 0, sizeof(*info));
    info->proto = r32(p); info->min_proto = r32(p + 4);
    if (info->proto < 5) return -1;        /* 1-byte codec format, unsupported */
    n = p[8];
    info->n_streams = (int)n;
    off = 9;
    for (i = 0; i < n; i++) {
        u8 id, ty, en; u32 codec, fm;
        if (off + 9 > len) return -1;
        id = p[off]; ty = p[off + 1]; codec = r32(p + off + 2);
        fm = r16(p + off + 6); en = p[off + 8];
        off += 9;
        if (ty == 1 && en && !info->audio_stream_id) {
            info->audio_stream_id = id; info->audio_codec = codec; info->frame_ms = (u16)fm;
        }
    }
    return 0;
}

int tgcp_make_stream_data(const u8 *opus, u32 len, u32 pts, u8 *out, u32 cap)
{
    u32 o;
    if (len > 0x7FF) return TGCP_E_ARG;
    if (len <= 255) {
        if (cap < 6 + len) return TGCP_E_CAP;
        out[0] = 0x01; out[1] = (u8)len; o = 2;
    } else {
        if (cap < 7 + len) return TGCP_E_CAP;
        out[0] = 0x41; w16(out + 1, len); o = 3;   /* LEN16, no flag bits */
    }
    w32(out + o, pts); o += 4;
    if (len) memcpy(out + o, opus, len);
    return (int)(o + len);
}

/* :2510-2563 (X2/X3 = 2/3 consecutive frames; EXTRA_FEC trailer skipped) */
int tgcp_parse_stream_data(const u8 *p, u32 len, u8 *stream_id, u32 *pts,
                           const u8 **opus, u32 *opus_len)
{
    u32 off = 1, sdlen, i, fc;
    u8 b;
    if (len < 6) return -1;
    b = p[0];
    *stream_id = (u8)(b & 0x3F);
    if (b & 0x40) { sdlen = r16(p + 1); off = 3; }
    else { sdlen = p[1]; off = 2; }
    if (off + 4 > len) return -1;
    *pts = r32(p + off); off += 4;
    if (sdlen & 0x4000) return -2;         /* fragmented: video only */
    {
        int fec = (sdlen & 0x2000) != 0;
        sdlen &= 0x7FF;
        if (off + sdlen > len) return -1;
        *opus = p + off; *opus_len = sdlen;
        off += sdlen;
        if (fec) {
            if (off >= len) return -1;
            fc = p[off++];
            for (i = 0; i < fc; i++) {
                if (off >= len) return -1;
                off += 1 + p[off];
                if (off > len) return -1;
            }
        }
    }
    return (int)off;
}

int tgcp_make_ping(u8 *out, u32 cap) { (void)out; (void)cap; return 0; }
int tgcp_make_nop(u8 *out, u32 cap) { (void)out; (void)cap; return 0; }
int tgcp_make_pong(u32 ping_seq, u8 *out, u32 cap)
{
    if (cap < 4) return TGCP_E_CAP;
    w32(out, ping_seq);
    return 4;
}

int tgcp_send_audio(tgcp_ctx *c, const u8 *opus, u32 len, u8 *out, u32 cap)
{
    u8 pl[TGCP_MAX_PAYLOAD];
    int n;
    if (c->state != TGCP_ST_CONNECTED) return TGCP_E_STATE;
    n = tgcp_make_stream_data(opus, len, c->pts_out, pl, sizeof(pl));
    if (n < 0) return n;
    n = tgcp_build_datagram(c, TGCP_PKT_STREAM_DATA, pl, (u32)n, out, cap);
    if (n > 0) c->pts_out += TGCP_FRAME_MS;      /* :1250 */
    return n;
}

/* ------------------------------------------------------------ reflector */

int tgcp_make_reflector_ping(const u8 *peer_tag, const u8 *id8, u8 *out, u32 cap)
{
    if (cap < 40) return TGCP_E_CAP;
    memcpy(out, peer_tag, 16);
    w32(out + 16, 0xFFFFFFFFUL); w32(out + 20, 0xFFFFFFFFUL);
    w32(out + 24, 0xFFFFFFFFUL); w32(out + 28, 0xFFFFFFFEUL);   /* -1,-1,-1,-2 :3326 */
    memcpy(out + 32, id8, 8);
    return 40;
}

/* reply: tag||FF*12||u32 tlid 0xc01572c7||i32 date||i64 query||ip16||port (:1871-1900) */
int tgcp_is_reflector_reply(const u8 *in, u32 len, u8 *query_id8)
{
    u32 i;
    if (len < 28) return 0;
    for (i = 16; i < 28; i++) if (in[i] != 0xFF) return 0;
    if (len >= 32 + 4 + 8 + 16 + 4 && r32(in + 28) == 0xC01572C7UL) {
        if (query_id8) memcpy(query_id8, in + 36, 8);
        return 1;
    }
    return 2;
}

/* ------------------------------------------------------------ timing */

static int tick_build(tgcp_ctx *c, u8 type, const u8 *pl, u32 n, u8 *out, u32 cap)
{
    return tgcp_build_datagram(c, type, pl, n, out, cap);
}

int tgcp_tick(tgcp_ctx *c, u32 now_ms, u8 *out, u32 out_cap)
{
    u8 pl[24];
    int n;
    tgcp_set_now(c, now_ms);
    if (c->state == TGCP_ST_FAILED) return 0;

    if (c->state == TGCP_ST_INIT_SENT && (u32)(now_ms - c->start_ms) >= TGCP_INIT_TIMEOUT_MS) {
        c->state = TGCP_ST_FAILED; c->fail_reason = 0;       /* :1010 */
        return 0;
    }
    if (c->state == TGCP_ST_CONNECTED && (u32)(now_ms - c->last_rx_ms) >= TGCP_RECV_TIMEOUT_MS) {
        c->state = TGCP_ST_FAILED; c->fail_reason = 0;       /* :3764 */
        return 0;
    }
    if (c->pend_init_ack) {
        c->pend_init_ack = 0;
        n = tgcp_make_init_ack(pl, sizeof(pl));
        return tick_build(c, TGCP_PKT_INIT_ACK, pl, (u32)n, out, out_cap);
    }
    if (c->pend_pong) {
        c->pend_pong = 0;
        n = tgcp_make_pong(c->pong_seq, pl, sizeof(pl));
        return tick_build(c, TGCP_PKT_PONG, pl, (u32)n, out, out_cap);
    }
    if (c->state == TGCP_ST_INIT_SENT && !c->got_init_ack &&
        (!c->init_sent_once || (u32)(now_ms - c->last_init_ms) >= TGCP_INIT_RETRY_MS)) {
        c->init_sent_once = 1;
        c->last_init_ms = now_ms;
        n = tgcp_make_init(pl, sizeof(pl));
        return tick_build(c, TGCP_PKT_INIT, pl, (u32)n, out, out_cap);   /* new seq per retry */
    }
    if (c->unack_in > TGCP_NOP_THRESHOLD)                     /* :2289 */
        return tick_build(c, TGCP_PKT_NOP, 0, 0, out, out_cap);
    if (c->state == TGCP_ST_CONNECTED && (u32)(now_ms - c->last_ping_ms) >= TGCP_PING_MS) {
        c->last_ping_ms = now_ms;
        return tick_build(c, TGCP_PKT_PING, 0, 0, out, out_cap);
    }
    return 0;
}

int tgcp_get_state(const tgcp_ctx *c) { return c->state; }
int tgcp_is_reconnecting(const tgcp_ctx *c)
{
    return c->state == TGCP_ST_CONNECTED && (u32)(c->now - c->last_rx_ms) >= TGCP_RECONNECT_MS;
}
u32 tgcp_unacked_out(const tgcp_ctx *c) { return c->unacked_out; }
u32 tgcp_last_rx_seq(const tgcp_ctx *c) { return c->last_rx_seq; }
int tgcp_got_init(const tgcp_ctx *c) { return c->got_init; }
int tgcp_got_init_ack(const tgcp_ctx *c) { return c->got_init_ack; }
