/* c277_rtp.c - see c277_rtp.h. RTP per RFC 3550, Opus payload per RFC 7587. */
#include <string.h>
#include "c277_rtp.h"

u32 c277_opus_samples48k(const u8 *p, u32 n)
{
    u32 cfg, per, frames;
    if (n < 1) return 0;
    cfg = p[0] >> 3;
    if (cfg < 12) { static const u32 s[4] = {480, 960, 1920, 2880}; per = s[cfg & 3]; }
    else if (cfg < 16) per = (cfg & 1) ? 960 : 480;
    else { static const u32 c[4] = {120, 240, 480, 960}; per = c[cfg & 3]; }
    switch (p[0] & 3) {
    case 0: frames = 1; break;
    case 1: case 2: frames = 2; break;
    default:
        if (n < 2) return 0;
        frames = p[1] & 0x3F;
        if (frames == 0) return 0;
        break;
    }
    if (per * frames > 5760) return 0;   /* max 120 ms */
    return per * frames;
}

void c277_rtp_tx_init(c277_rtp_tx *t, int is_outgoing, const u8 *r)
{
    t->ssrc = is_outgoing ? C277_RTP_SSRC_CALLER : C277_RTP_SSRC_CALLEE;
    t->seq = (u16)(((u32)r[0] << 8) | r[1]);
    t->ts = ((u32)r[2] << 24) | ((u32)r[3] << 16) | ((u32)r[4] << 8) | r[5];
}

int c277_rtp_tx_build(c277_rtp_tx *t, const u8 *opus, u32 n, u8 *out, u32 cap)
{
    u32 d;
    if (n == 0 || n > 65000UL || cap < 12 + n) return -1;
    out[0] = 0x80; out[1] = C277_RTP_PT;
    out[2] = (u8)(t->seq >> 8); out[3] = (u8)t->seq;
    out[4] = (u8)(t->ts >> 24); out[5] = (u8)(t->ts >> 16); out[6] = (u8)(t->ts >> 8); out[7] = (u8)t->ts;
    out[8] = (u8)(t->ssrc >> 24); out[9] = (u8)(t->ssrc >> 16); out[10] = (u8)(t->ssrc >> 8); out[11] = (u8)t->ssrc;
    memcpy(out + 12, opus, n);
    d = c277_opus_samples48k(opus, n);
    t->seq = (u16)(t->seq + 1);
    t->ts += d ? d : 2880UL;
    return (int)(12 + n);
}

int c277_rtp_parse(const u8 *p, u32 n, c277_rtp_hdr *h)
{
    u32 pos, cc, pad = 0;
    if (n < 12 || (p[0] >> 6) != 2) return -1;
    cc = p[0] & 15;
    h->marker = (p[1] >> 7) & 1;
    h->pt = p[1] & 0x7F;
    h->seq = (u16)(((u32)p[2] << 8) | p[3]);
    h->ts = ((u32)p[4] << 24) | ((u32)p[5] << 16) | ((u32)p[6] << 8) | p[7];
    h->ssrc = ((u32)p[8] << 24) | ((u32)p[9] << 16) | ((u32)p[10] << 8) | p[11];
    pos = 12 + 4 * cc;
    if (pos > n) return -1;
    if (p[0] & 0x10) {                      /* X: profile u16 | length-in-words u16 | words */
        u32 w;
        if (n - pos < 4) return -1;
        w = ((u32)p[pos + 2] << 8) | p[pos + 3];
        pos += 4;
        if (w * 4 > n - pos) return -1;
        pos += w * 4;
    }
    if (p[0] & 0x20) {                      /* P: last byte = padding count incl. itself */
        pad = p[n - 1];
        if (pad == 0 || pad > n - pos) return -1;
    }
    h->payload = p + pos;
    h->plen = n - pos - pad;
    return 0;
}

int c277_rtp_is_rtcp(const u8 *p, u32 n)
{
    return n >= 8 && (p[0] >> 6) == 2 && p[1] >= 192 && p[1] <= 223;
}

/* ---------------------------------------------------------------- jitter */

void c277_jb_init(c277_jb *jb) { memset(jb, 0, sizeof(*jb)); }

static void jb_drop_slot(c277_jb *jb, u16 seq)
{
    c277_jb_slot *s = &jb->slot[seq & (C277_JB_SLOTS - 1)];
    if (s->used) { s->used = 0; jb->count--; }
}

int c277_jb_put(c277_jb *jb, u16 seq, u32 ts, const u8 *data, u32 n)
{
    u32 d;
    c277_jb_slot *s;
    if (n > C277_JB_MAXPKT) { jb->n_big++; return 1; }
    if (!jb->started) { jb->started = 1; jb->next = seq; }
    d = (u16)(seq - jb->next);
    if (d >= 0x8000UL) { jb->n_late++; return 1; }
    if (d >= C277_JB_SLOTS) {
        if (d >= 3000UL) {                          /* stream restart / huge jump: resync */
            u32 i;
            for (i = 0; i < C277_JB_SLOTS; i++) jb->slot[i].used = 0;
            jb->count = 0; jb->next = seq; d = 0;
        } else {                                    /* overflow: drop the oldest to make room */
            while (d >= C277_JB_SLOTS) {
                if (jb->slot[jb->next & (C277_JB_SLOTS - 1)].used) jb->n_overflow++;
                jb_drop_slot(jb, jb->next);
                jb->next = (u16)(jb->next + 1);
                d--;
            }
        }
    }
    s = &jb->slot[seq & (C277_JB_SLOTS - 1)];
    if (s->used) { jb->n_dup++; return 1; }
    s->used = 1; s->seq = seq; s->ts = ts; s->len = n;
    if (n) memcpy(s->data, data, n);
    jb->count++;
    jb->n_in++;
    return 0;
}

int c277_jb_get(c277_jb *jb, u8 *out, u32 cap, u32 *len, u32 *ts_out)
{
    c277_jb_slot *s;
    u32 i, later = 0;
    if (!jb->started || jb->count == 0) return C277_JB_EMPTY;
    s = &jb->slot[jb->next & (C277_JB_SLOTS - 1)];
    if (s->used) {
        if (s->len > cap) { jb_drop_slot(jb, jb->next); jb->next = (u16)(jb->next + 1); return C277_JB_LOST; }
        memcpy(out, s->data, s->len);
        *len = s->len;
        if (ts_out) *ts_out = s->ts;
        jb_drop_slot(jb, jb->next);
        jb->next = (u16)(jb->next + 1);
        return C277_JB_PACKET;
    }
    for (i = 1; i < C277_JB_SLOTS; i++)
        if (jb->slot[(u16)(jb->next + i) & (C277_JB_SLOTS - 1)].used) later++;
    if (later >= C277_JB_REORDER || jb->count >= C277_JB_SLOTS - 1) {
        jb->next = (u16)(jb->next + 1);
        jb->n_lost++;
        *len = 0;
        return C277_JB_LOST;
    }
    return C277_JB_EMPTY;
}

int c277_jb_depth(const c277_jb *jb) { return jb->count; }
