/* c277_video.c - see c277_video.h */
#include <string.h>
#include "c277_video.h"

/* ---------------------------------------------------------------- Annex-B */

int c277_annexb_split(const u8 *d, u32 n, c277_nal *out, u32 max)
{
    u32 i = 0, start = 0, cnt = 0;
    int have = 0;
    if (n == 0 || max == 0) return 0;
    while (i + 2 < n) {
        if (d[i] == 0 && d[i + 1] == 0 && d[i + 2] == 1) {
            if (have && cnt < max) {
                u32 e = i;
                while (e > start && d[e - 1] == 0) e--;     /* 4-byte start code / trailing zeros */
                out[cnt].off = start; out[cnt].len = e - start; cnt++;
            }
            start = i + 3; have = 1; i += 3;
        } else {
            i++;
        }
    }
    if (!have) {
        out[0].off = 0; out[0].len = n;
        return 1;
    }
    if (cnt < max && start < n) {
        u32 e = n;
        while (e > start && d[e - 1] == 0) e--;
        out[cnt].off = start; out[cnt].len = e - start; cnt++;
    }
    {   /* drop empty entries */
        u32 a, b = 0;
        for (a = 0; a < cnt; a++) if (out[a].len > 0) out[b++] = out[a];
        cnt = b;
    }
    return (int)cnt;
}

/* ---------------------------------------------------------------- SPS */

typedef struct { const u8 *p; u32 n, pos; int err; } bitr;

static u32 br_bit(bitr *b)
{
    u32 v;
    if ((b->pos >> 3) >= b->n) { b->err = 1; return 0; }
    v = (b->p[b->pos >> 3] >> (7 - (b->pos & 7))) & 1;
    b->pos++;
    return v;
}
static u32 br_ue_full(bitr *b)
{
    u32 z = 0, v = 0, i;
    while (br_bit(b) == 0) {
        if (b->err || ++z > 31) { b->err = 1; return 0; }
    }
    for (i = 0; i < z; i++) v = (v << 1) | br_bit(b);
    return (z ? ((1UL << z) - 1) : 0) + v;
}
static int br_se(bitr *b)
{
    u32 k = br_ue_full(b);
    return (k & 1) ? (int)((k + 1) >> 1) : -(int)(k >> 1);
}

static void skip_scaling(bitr *b, int size)
{
    int last = 8, next = 8, j;
    for (j = 0; j < size && !b->err; j++) {
        if (next != 0) {
            int d = br_se(b);
            next = (last + d + 256) & 255;
        }
        if (next != 0) last = next;
    }
}

int c277_sps_parse(const u8 *nal, u32 n, c277_sps *o)
{
    u8 rb[160];
    u32 i, m = 0, chroma = 1, fmo, pw, ph, cl = 0, cr = 0, ct = 0, cb = 0, cux, cuy;
    int prof, k;
    bitr b;
    memset(o, 0, sizeof(*o));
    if (n < 5 || (nal[0] & 31) != 7) return -1;
    /* unescape (drop the 03 of 00 00 03) */
    for (i = 1; i < n && m < sizeof(rb); i++) {
        if (i >= 3 && nal[i] == 3 && nal[i - 1] == 0 && nal[i - 2] == 0) continue;
        rb[m++] = nal[i];
    }
    b.p = rb; b.n = m; b.pos = 0; b.err = 0;
    prof = rb[0];
    o->profile = prof; o->constraints = rb[1]; o->level = rb[2];
    b.pos = 24;
    br_ue_full(&b);                                   /* sps id */
    if (prof == 100 || prof == 110 || prof == 122 || prof == 244 || prof == 44 || prof == 83 ||
        prof == 86 || prof == 118 || prof == 128 || prof == 138 || prof == 139 || prof == 134 ||
        prof == 135) {
        chroma = br_ue_full(&b);
        if (chroma == 3) br_bit(&b);
        br_ue_full(&b); br_ue_full(&b); br_bit(&b);
        if (br_bit(&b)) {
            int cnt = chroma != 3 ? 8 : 12;
            for (k = 0; k < cnt && !b.err; k++)
                if (br_bit(&b)) skip_scaling(&b, k < 6 ? 16 : 64);
        }
    }
    br_ue_full(&b);                                   /* log2_max_frame_num - 4 */
    k = (int)br_ue_full(&b);                          /* poc type */
    if (k == 0) br_ue_full(&b);
    else if (k == 1) {
        u32 cnt, j;
        br_bit(&b); br_se(&b); br_se(&b);
        cnt = br_ue_full(&b);
        if (cnt > 255) b.err = 1;
        for (j = 0; j < cnt && !b.err; j++) br_se(&b);
    }
    br_ue_full(&b);                                   /* max_num_ref_frames */
    br_bit(&b);                                       /* gaps allowed */
    pw = br_ue_full(&b);
    ph = br_ue_full(&b);
    fmo = br_bit(&b);
    if (!fmo) br_bit(&b);
    br_bit(&b);                                       /* direct 8x8 */
    if (br_bit(&b)) { cl = br_ue_full(&b); cr = br_ue_full(&b); ct = br_ue_full(&b); cb = br_ue_full(&b); }
    if (b.err || pw > 1000 || ph > 1000) return -1;
    if (chroma == 0) { cux = 1; cuy = 2 - fmo; }
    else {
        cux = chroma == 3 ? 1 : 2;
        cuy = (chroma == 1 ? 2 : 1) * (2 - fmo);
    }
    o->width = (int)((pw + 1) * 16 - cux * (cl + cr));
    o->height = (int)((2 - fmo) * (ph + 1) * 16 - cuy * (ct + cb));
    o->ok = 1;
    return 0;
}

/* ---------------------------------------------------------------- sender */

static void put16(u8 *p, u32 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void put32(u8 *p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }

void c277_vtx_init(c277_vtx *v, u32 ssrc, const u8 *rnd6)
{
    memset(v, 0, sizeof(*v));
    v->ssrc = ssrc;
    v->seq = (u16)(((u32)rnd6[0] << 8) | rnd6[1]);
    v->ts_base = ((u32)rnd6[2] << 24) | ((u32)rnd6[3] << 16) | ((u32)rnd6[4] << 8) | rnd6[5];
    v->tseq = (u16)(rnd6[0] ^ (rnd6[5] << 4));
}

void c277_vtx_reset(c277_vtx *v)
{
    v->pending = 0; v->n_nal = 0; v->sent_idr = 0;
}

u32 c277_vtx_ts_at(const c277_vtx *v, u32 now)
{
    if (!v->started) return v->ts_base;
    return v->ts_base + (u32)(now - v->t0) * 90UL;
}

static void keep_ps(u8 *dst, u32 *dl, const u8 *src, u32 n)
{
    if (n > 0 && n <= C277_VPS_MAX) { memcpy(dst, src, n); *dl = n; }
}

int c277_vtx_put(c277_vtx *v, const u8 *unit, u32 n, u32 now)
{
    c277_nal nl[C277_VNAL_MAX];
    int cnt, i, vcl = 0, idr = 0, keep = 0;
    u32 pos = 0;
    if (v->pending) { v->n_drop++; return C277_VTX_DROPPED; }
    if (n == 0 || n > C277_VAU_MAX) { v->n_drop++; return C277_VTX_DROPPED; }
    cnt = c277_annexb_split(unit, n, nl, C277_VNAL_MAX);
    /* first pass: parameter sets, what is VCL, is it an IDR */
    for (i = 0; i < cnt; i++) {
        int t = unit[nl[i].off] & 31;
        if (nl[i].len == 0) continue;
        if (t == 7) { keep_ps(v->sps, &v->sps_len, unit + nl[i].off, nl[i].len); v->n_params++; }
        else if (t == 8) keep_ps(v->pps, &v->pps_len, unit + nl[i].off, nl[i].len);
        else if (t >= 1 && t <= 5) { vcl = 1; if (t == 5) idr = 1; }
    }
    if (!vcl) return C277_VTX_PARAMS;
    if (idr && (v->sps_len == 0 || v->pps_len == 0)) { v->n_drop++; v->n_drop_idr++; return C277_VTX_DROPPED; }
    if (!idr && !v->sent_idr) { v->n_drop++; return C277_VTX_DROPPED; }
    /* keep the VCL (and other non-parameter, non-SEI/AUD) NAL units */
    v->n_nal = 0;
    for (i = 0; i < cnt; i++) {
        int t = unit[nl[i].off] & 31;
        if (nl[i].len == 0 || t == 7 || t == 8 || t == 6 || t == 9 || t == 12 || t > 5) continue;
        if (pos + nl[i].len > C277_VAU_MAX) break;
        memcpy(v->au + pos, unit + nl[i].off, nl[i].len);
        v->nal[v->n_nal].off = pos; v->nal[v->n_nal].len = nl[i].len;
        v->n_nal++; pos += nl[i].len; keep = 1;
    }
    if (!keep) return C277_VTX_PARAMS;
    if (!v->started) { v->started = 1; v->t0 = now; }
    v->au_ts = c277_vtx_ts_at(v, now);
    v->idr = idr;
    v->it_nal = 0; v->it_off = 0; v->it_stap = idr ? 1 : 0;
    v->pending = 1;
    if (idr) { v->sent_idr = 1; v->n_idr++; }
    v->n_au++;
    return C277_VTX_QUEUED;
}

/* RTP header (12) + one-byte extension header with the transport-cc seq (8). */
static u32 rtp_head(c277_vtx *v, u8 *o, int marker)
{
    o[0] = 0x90;                                  /* V=2 X=1 */
    o[1] = (u8)((marker ? 0x80 : 0) | C277_VPT);
    put16(o + 2, v->seq); v->seq = (u16)(v->seq + 1);
    put32(o + 4, v->au_ts);
    put32(o + 8, v->ssrc);
    o[12] = 0xBE; o[13] = 0xDE; o[14] = 0; o[15] = 1;
    o[16] = (u8)((C277_VEXT_ID << 4) | 1);        /* id 2, 2 bytes */
    put16(o + 17, v->tseq); v->tseq = (u16)(v->tseq + 1);
    o[19] = 0;
    return 20;
}

int c277_vtx_next(c277_vtx *v, u8 *out, u32 cap)
{
    u32 h, plen;
    int last;
    if (!v->pending || cap < 20 + C277_VMTU + 4) return 0;
    if (v->it_stap) {
        /* STAP-A: SPS + PPS ahead of an IDR */
        u8 nri = (u8)(v->sps[0] & 0x60);
        h = rtp_head(v, out, 0);
        out[h] = (u8)(nri | 24);
        put16(out + h + 1, v->sps_len); memcpy(out + h + 3, v->sps, v->sps_len);
        put16(out + h + 3 + v->sps_len, v->pps_len);
        memcpy(out + h + 5 + v->sps_len, v->pps, v->pps_len);
        plen = 1 + 2 + v->sps_len + 2 + v->pps_len;
        v->it_stap = 0;
        v->n_pk++; v->n_oct += plen;
        return (int)(h + plen);
    }
    {
        const c277_nal *nl = &v->nal[v->it_nal];
        const u8 *nal = v->au + nl->off;
        last = v->it_nal == v->n_nal - 1;
        if (nl->len <= C277_VMTU) {
            h = rtp_head(v, out, last);
            memcpy(out + h, nal, nl->len);
            plen = nl->len;
            v->it_nal++;
        } else {
            u32 left = nl->len - 1 - v->it_off, chunk = C277_VMTU - 2;
            int first = v->it_off == 0, end;
            if (left <= chunk) { chunk = left; end = 1; } else end = 0;
            h = rtp_head(v, out, last && end);
            out[h] = (u8)((nal[0] & 0x60) | 28);
            out[h + 1] = (u8)((first ? 0x80 : 0) | (end ? 0x40 : 0) | (nal[0] & 31));
            memcpy(out + h + 2, nal + 1 + v->it_off, chunk);
            plen = chunk + 2;
            v->it_off += chunk;
            if (end) { v->it_nal++; v->it_off = 0; }
        }
    }
    if (v->it_nal >= v->n_nal) v->pending = 0;
    v->n_pk++; v->n_oct += plen;
    return (int)(h + plen);
}

/* ---------------------------------------------------------------- RTCP */

int c277_rtcp_build_sr(u8 *out, u32 cap, u32 ssrc, u32 ntp_hi, u32 ntp_lo, u32 rtp_ts, u32 pk, u32 oct)
{
    static const u8 sdes_tail[] = { 0x01, 0x05, 'c', 'n', 'a', 'm', 'e', 0x00 };
    if (cap < 44) return -1;
    out[0] = 0x80; out[1] = 200; put16(out + 2, 6);
    put32(out + 4, ssrc); put32(out + 8, ntp_hi); put32(out + 12, ntp_lo);
    put32(out + 16, rtp_ts); put32(out + 20, pk); put32(out + 24, oct);
    out[28] = 0x81; out[29] = 202; put16(out + 30, 3);
    put32(out + 32, ssrc);
    memcpy(out + 36, sdes_tail, 8);
    return 44;
}

int c277_rtcp_build_pli(u8 *out, u32 cap, u32 sender, u32 media)
{
    if (cap < 12) return -1;
    out[0] = 0x81; out[1] = 206; put16(out + 2, 2);
    put32(out + 4, sender); put32(out + 8, media);
    return 12;
}

static u32 get32(const u8 *p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }

int c277_rtcp_parse(const u8 *p, u32 n, u32 our_ssrc, c277_rtcp_info *o)
{
    u32 pos = 0;
    memset(o, 0, sizeof(*o));
    while (pos + 4 <= n) {
        u32 words, len, fmt, pt;
        const u8 *q = p + pos;
        if ((q[0] >> 6) != 2) return -1;
        fmt = q[0] & 31; pt = q[1];
        words = ((u32)q[2] << 8) | q[3];
        len = (words + 1) * 4;
        if (pos + len > n) return -1;
        if (pt == 200) o->n_sr++;
        else if (pt == 201) {
            u32 rc = fmt, k;
            o->n_rr++;
            for (k = 0; k < rc && 8 + 24 * (k + 1) <= len; k++) {
                const u8 *r = q + 8 + 24 * k;
                if (our_ssrc == 0 || get32(r) == our_ssrc) {
                    o->rr_have = 1; o->rr_fraction = r[4];
                    o->rr_lost = ((u32)r[5] << 16) | ((u32)r[6] << 8) | r[7];
                    o->rr_jitter = get32(r + 16);
                }
            }
        } else if (pt == 206 && len >= 12) {
            u32 media = get32(q + 8);
            if (fmt == 1 || fmt == 4) {
                if (our_ssrc == 0 || media == our_ssrc || media == 0) { if (fmt == 1) o->n_pli++; else o->n_fir++; }
                else if (fmt == 4 && len >= 16 && get32(q + 12) == our_ssrc) o->n_fir++;
            } else if (fmt == 15) o->n_remb++;
            else o->n_other++;
        } else if (pt == 205 && len >= 12) {
            if (fmt == 1) {
                if (our_ssrc == 0 || get32(q + 8) == our_ssrc) {
                    u32 k;
                    o->n_nack++;
                    for (k = 12; k + 4 <= len; k += 4) {
                        u32 pid = ((u32)q[k] << 8) | q[k + 1], blp = ((u32)q[k + 2] << 8) | q[k + 3], b;
                        if (o->n_nack_seq < C277_NACK_SEQ_MAX) o->nack_seq[o->n_nack_seq++] = (u16)pid;
                        for (b = 0; b < 16; b++)
                            if ((blp >> b) & 1 && o->n_nack_seq < C277_NACK_SEQ_MAX)
                                o->nack_seq[o->n_nack_seq++] = (u16)(pid + 1 + b);
                    }
                }
            }
            else if (fmt == 15) o->n_twcc++;
            else o->n_other++;
        } else {
            o->n_other++;
        }
        pos += len;
    }
    return 0;
}

int c277_rtcp_build_rr(u8 *out, u32 cap, u32 sender, u32 media, u32 fraction, u32 cum_lost,
                       u32 ext_hi_seq, u32 jitter)
{
    if (cap < 32) return -1;
    out[0] = 0x81; out[1] = 201; put16(out + 2, 7);
    put32(out + 4, sender); put32(out + 8, media);
    out[12] = (u8)fraction; out[13] = (u8)(cum_lost >> 16); out[14] = (u8)(cum_lost >> 8); out[15] = (u8)cum_lost;
    put32(out + 16, ext_hi_seq); put32(out + 20, jitter);
    put32(out + 24, 0); put32(out + 28, 0);          /* no SR seen: LSR / DLSR 0 */
    return 32;
}

/* REMB: bitrate = mantissa(18 bit) << exp(6 bit) */
int c277_rtcp_build_remb(u8 *out, u32 cap, u32 sender, u32 media, u32 bitrate_bps)
{
    u32 exp = 0, man = bitrate_bps;
    if (cap < 24) return -1;
    while (man > 0x3FFFFUL) { man >>= 1; exp++; }
    out[0] = 0x8F; out[1] = 206; put16(out + 2, 5);
    put32(out + 4, sender); put32(out + 8, 0);
    out[12] = 'R'; out[13] = 'E'; out[14] = 'M'; out[15] = 'B';
    out[16] = 1;
    out[17] = (u8)((exp << 2) | (man >> 16));
    out[18] = (u8)(man >> 8); out[19] = (u8)man;
    put32(out + 20, media);
    return 24;
}

/* ---------------------------------------------------------------- receiver */

void c277_vrx_init(c277_vrx *v)
{
    memset(v, 0, sizeof(*v));
    v->need_idr = 1;
}

static void vrx_damage(c277_vrx *v)
{
    if (v->in_au) v->n_drop_au++;
    v->in_au = 0; v->au_len = 0; v->au_ok = 0; v->fu_open = 0; v->au_idr = v->au_sps = v->au_pps = 0;
    v->need_idr = 1; v->need_pli = 1;
}

static int vrx_append(c277_vrx *v, const u8 *nal, u32 n, int open_only)
{
    u32 need = n + (open_only ? 0 : 4);
    if (v->au_len + need > C277_VRX_AU_MAX) { v->au_ok = 0; return -1; }
    if (!open_only) {
        v->au[v->au_len] = 0; v->au[v->au_len + 1] = 0; v->au[v->au_len + 2] = 0; v->au[v->au_len + 3] = 1;
        v->au_len += 4;
    }
    memcpy(v->au + v->au_len, nal, n);
    v->au_len += n;
    return 0;
}

static void vrx_nal(c277_vrx *v, const u8 *nal, u32 n)
{
    int t;
    if (n == 0) return;
    t = nal[0] & 31;
    if (t == 7) {
        if (n <= C277_VPS_MAX) {
            if (n != v->sps_len || memcmp(v->sps, nal, n) != 0) v->sps_changed = 1;
            memcpy(v->sps, nal, n); v->sps_len = n;
        }
        v->au_sps = 1;
    } else if (t == 8) {
        if (n <= C277_VPS_MAX) { memcpy(v->pps, nal, n); v->pps_len = n; }
        v->au_pps = 1;
    } else if (t == 5) v->au_idr = 1;
    vrx_append(v, nal, n, 0);
}

static void vrx_finish(c277_vrx *v)
{
    /* the access unit is complete (marker seen) */
    v->in_au = 0;
    if (!v->au_ok || v->au_len == 0) { vrx_damage(v); return; }
    if (v->need_idr && !v->au_idr) { v->au_len = 0; v->au_idr = v->au_sps = v->au_pps = 0; v->n_wait++; v->need_pli = 1; return; }
    if (v->au_idr && !(v->au_sps && v->au_pps)) {
        /* IDR without parameter sets: prepend the cached ones */
        u32 add = 0;
        if (v->sps_len == 0 || v->pps_len == 0) { v->au_len = 0; v->au_idr = v->au_sps = v->au_pps = 0; v->need_pli = 1; return; }
        if (!v->au_sps) add += 4 + v->sps_len;
        if (!v->au_pps) add += 4 + v->pps_len;
        if (v->au_len + add > C277_VRX_AU_MAX) { vrx_damage(v); return; }
        memmove(v->au + add, v->au, v->au_len);
        add = 0;
        if (!v->au_sps) { v->au[0] = 0; v->au[1] = 0; v->au[2] = 0; v->au[3] = 1; memcpy(v->au + 4, v->sps, v->sps_len); add = 4 + v->sps_len; }
        if (!v->au_pps) { v->au[add] = 0; v->au[add + 1] = 0; v->au[add + 2] = 0; v->au[add + 3] = 1; memcpy(v->au + add + 4, v->pps, v->pps_len); add += 4 + v->pps_len; }
        v->au_len += add;
    }
    if (v->au_idr) { v->need_idr = 0; v->n_idr++; }
    v->ready = 1; v->ready_len = v->au_len; v->ready_idr = v->au_idr; v->ready_ts = v->au_ts;
    v->n_au++;
    v->au_len = 0; v->au_ok = 0; v->au_idr = v->au_sps = v->au_pps = 0;
}

static void vrx_drain(c277_vrx *v);
static void vrx_nack_list(c277_vrx *v);
static void vrx_skip_gap(c277_vrx *v, u32 now);
void c277_vrx_done(c277_vrx *v) { v->ready = 0; vrx_drain(v); }

static void vrx_process(c277_vrx *v, u16 seq, u32 ts, int marker, const u8 *p, u32 n);

int c277_vrx_put(c277_vrx *v, u16 seq, u32 ts, int marker, u32 ssrc, const u8 *p, u32 n, u32 now)
{
    u16 d;
    int i, free_i = -1;
    if (n < 1) return 0;
    if (v->ready) { v->ready = 0; v->n_drop_au++; }          /* the consumer was too slow: drop that unit */
    if (!v->started || ssrc != v->ssrc) {
        memset(v->slot, 0, sizeof(v->slot)); v->nbuf = 0; v->gap_t = 0; v->n_nack = 0;
        v->started = 1; v->ssrc = ssrc; v->next_seq = seq; v->au_len = 0; v->au_ok = 0; v->fu_open = 0; v->in_au = 0;
        v->need_idr = 1; v->need_pli = 1;
        v->base_seq = seq; v->max_ext = seq; v->received = 0; v->expected_prior = 0; v->received_prior = 0;
    }
    d = (u16)(seq - v->next_seq);
    if (d >= 0x8000) { v->n_late++; return 0; }              /* late or duplicate */
    {   /* statistics count every packet that arrives (also those still waiting in the buffer) */
        u32 cyc = v->max_ext & 0xFFFF0000UL, low = v->max_ext & 0xFFFFUL;
        if (seq < low && low - seq > 0x8000UL) cyc += 0x10000UL;
        if ((cyc | seq) > v->max_ext) v->max_ext = cyc | seq;
        v->received++;
    }
    if (d == 0) {
        vrx_process(v, seq, ts, marker, p, n);
        vrx_drain(v);
        return v->ready;
    }
    /* ahead of a gap: keep it until the missing packets show up or the wait is over */
    v->n_reordered++;
    if (n > C277_VRX_PKT_MAX) { v->n_big++; }
    else {
        for (i = 0; i < C277_VRX_SLOTS; i++) {
            if (v->slot[i].used && v->slot[i].seq == seq) { free_i = -2; break; }
            if (!v->slot[i].used && free_i == -1) free_i = i;
        }
        if (free_i >= 0) {
            v->slot[free_i].used = 1; v->slot[free_i].seq = seq; v->slot[free_i].len = (u16)n;
            v->slot[free_i].ts = ts; v->slot[free_i].marker = (u8)(marker != 0);
            memcpy(v->slot[free_i].d, p, n);
            v->nbuf++;
        }
    }
    if (v->gap_t == 0) v->gap_t = now ? now : 1;
    vrx_nack_list(v);
    if (v->nbuf >= 8 || free_i == -1 || (u32)(now - v->gap_t) >= C277_VRX_GAP_MS) vrx_skip_gap(v, now);
    return v->ready;
}

int c277_vrx_tick(c277_vrx *v, u32 now)
{
    if (v->nbuf > 0 && v->gap_t != 0 && (u32)(now - v->gap_t) >= C277_VRX_GAP_MS) vrx_skip_gap(v, now);
    return v->ready;
}

static void vrx_process(c277_vrx *v, u16 seq, u32 ts, int marker, const u8 *p, u32 n)
{
    int t;
    v->next_seq = (u16)(seq + 1);
    v->n_pk++;
    if (v->in_au && ts != v->au_ts) vrx_damage(v);           /* the marker packet is missing */
    if (!v->in_au) { v->in_au = 1; v->au_ts = ts; v->au_ok = 1; }
    t = p[0] & 31;
    if (t >= 1 && t <= 23) {
        vrx_nal(v, p, n);
    } else if (t == 24) {
        u32 pos = 1;
        while (pos + 2 <= n) {
            u32 sz = ((u32)p[pos] << 8) | p[pos + 1];
            if (sz == 0 || pos + 2 + sz > n) { v->au_ok = 0; break; }
            vrx_nal(v, p + pos + 2, sz);
            pos += 2 + sz;
        }
    } else if (t == 28 && n >= 2) {
        int start = (p[1] & 0x80) != 0, end = (p[1] & 0x40) != 0;
        if (start) {
            u8 hdr = (u8)((p[0] & 0xE0) | (p[1] & 31));
            if (v->fu_open) v->au_ok = 0;
            v->fu_open = 1;
            if ((hdr & 31) == 5) v->au_idr = 1;
            if (vrx_append(v, &hdr, 1, 0) == 0) vrx_append(v, p + 2, n - 2, 1);
        } else if (!v->fu_open) {
            v->au_ok = 0;
        } else {
            vrx_append(v, p + 2, n - 2, 1);
        }
        if (end) v->fu_open = 0;
    } else {
        /* STAP-B, MTAP, FU-B, unknown: not used by WebRTC */
        v->au_ok = 0;
    }
    if (marker) {
        if (!v->au_ok) vrx_damage(v); else vrx_finish(v);
        v->fu_open = 0; v->in_au = 0;
    }
}

/* process buffered packets that are now in sequence; stops once an access unit is ready */
static void vrx_drain(c277_vrx *v)
{
    int i, found = 1;
    while (found && !v->ready && v->nbuf > 0) {
        found = 0;
        for (i = 0; i < C277_VRX_SLOTS; i++) {
            if (v->slot[i].used && v->slot[i].seq == v->next_seq) {
                v->slot[i].used = 0; v->nbuf--;
                vrx_process(v, v->slot[i].seq, v->slot[i].ts, v->slot[i].marker, v->slot[i].d, v->slot[i].len);
                found = 1;
                break;
            }
        }
    }
    if (v->nbuf == 0) { v->gap_t = 0; v->n_nack = 0; }
    else vrx_nack_list(v);
}

/* the missing packets in front of the oldest buffered one (for a NACK) */
static void vrx_nack_list(c277_vrx *v)
{
    int i;
    u16 best = 0, m;
    int have = 0;
    v->n_nack = 0;
    for (i = 0; i < C277_VRX_SLOTS; i++) {
        if (!v->slot[i].used) continue;
        if (!have || (u16)(v->slot[i].seq - v->next_seq) < (u16)(best - v->next_seq)) { best = v->slot[i].seq; have = 1; }
    }
    if (!have) return;
    for (m = v->next_seq; m != best && v->n_nack < C277_VRX_NACK_MAX; m++) {
        int held = 0;
        for (i = 0; i < C277_VRX_SLOTS; i++) if (v->slot[i].used && v->slot[i].seq == m) held = 1;
        if (!held) v->nack[v->n_nack++] = m;
    }
}

/* give up waiting: the packets in front of the oldest buffered one are lost */
static void vrx_skip_gap(c277_vrx *v, u32 now)
{
    int i, have = 0;
    u16 best = 0;
    for (i = 0; i < C277_VRX_SLOTS; i++) {
        if (!v->slot[i].used) continue;
        if (!have || (u16)(v->slot[i].seq - v->next_seq) < (u16)(best - v->next_seq)) { best = v->slot[i].seq; have = 1; }
    }
    if (!have) { v->gap_t = 0; return; }
    v->n_lost += (u16)(best - v->next_seq);
    v->n_gap_timeout++;
    vrx_damage(v);
    v->next_seq = best;
    v->gap_t = 0;
    vrx_drain(v);
    if (v->nbuf > 0) v->gap_t = now ? now : 1;
}

void c277_vrx_stats(c277_vrx *v, u32 *fraction, u32 *cum_lost, u32 *ext_hi)
{
    u32 expected = v->max_ext - v->base_seq + 1, lost, ep, rp;
    ep = expected - v->expected_prior; rp = v->received - v->received_prior;
    v->expected_prior = expected; v->received_prior = v->received;
    lost = expected > v->received ? expected - v->received : 0;
    *fraction = (ep > rp && ep > 0) ? ((ep - rp) * 256UL) / ep : 0;
    if (*fraction > 255) *fraction = 255;
    *cum_lost = lost & 0xFFFFFFUL;
    *ext_hi = v->max_ext;
}

int c277_rtcp_build_nack(u8 *out, u32 cap, u32 sender, u32 media, u32 pid, u32 blp)
{
    if (cap < 16) return -1;
    out[0] = 0x81; out[1] = 205; put16(out + 2, 3);
    put32(out + 4, sender); put32(out + 8, media);
    put16(out + 12, pid); put16(out + 14, blp);
    return 16;
}
