/* Host tests for c277_video: SPS decoding, RFC 6184 packetizer, RTCP builder/parser.
 * The byte strings marked "capture" are packets seen in a real call with an official
 * app (plain RTP/RTCP inside the transport message; no keys, no addresses). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c277_video.h"
#include "c277_rtp.h"

static int g_fail = 0, g_n = 0;
#define CHECK(cond) do { g_n++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static int unhex(const char *h, u8 *o, u32 cap)
{
    u32 n = 0;
    while (h[0] && h[1] && n < cap) {
        unsigned v;
        sscanf(h, "%2x", &v); o[n++] = (u8)v; h += 2;
    }
    return (int)n;
}

/* capture: official app (callee, SSRC 3), first packet of an IDR access unit: STAP-A SPS+PPS */
static const char *CAP_STAP3 =
    "9060508d2a23af1400000003bede0001210012007800136764001fac1b1a80841e69a81010103c2211a8000468ea43cb";
/* capture: second call, official app as caller (SSRC 4): smaller picture */
static const char *CAP_STAP4 =
    "906058cb9e144ccd00000004bede00012100390078001367640016ac1b1a816051a6a0404040f08846a0000468ea43cb";
/* capture: the official app's sender report for its video SSRC 3 (SR + SDES CNAME) */
static const char *CAP_SR =
    "80c8000600000003eeae2a89f58127b22a23de30000000000000000081ca0003000000030105636e616d6500";
static const char *CAP_RR = "80c9000100000001";

static void test_sps(void)
{
    u8 p[100];
    int n;
    c277_rtp_hdr h;
    c277_sps sp;
    n = unhex(CAP_STAP3, p, sizeof(p));
    CHECK(n == 48);
    CHECK(c277_rtp_parse(p, (u32)n, &h) == 0);
    CHECK(h.pt == 96 && h.ssrc == 3 && h.seq == 20621 && h.ts == 706981652UL && !h.marker);
    CHECK(h.payload[0] == 0x78 && h.plen == 28);       /* extension (bede, id 2) skipped */
    CHECK(h.payload[1] == 0 && h.payload[2] == 0x13);
    CHECK(c277_sps_parse(h.payload + 3, 0x13, &sp) == 0);
    CHECK(sp.profile == 100 && sp.level == 31 && sp.width == 528 && sp.height == 960);   /* High L3.1, 528x960 */
    n = unhex(CAP_STAP4, p, sizeof(p));
    CHECK(c277_rtp_parse(p, (u32)n, &h) == 0 && h.ssrc == 4);
    CHECK(c277_sps_parse(h.payload + 3, 0x13, &sp) == 0);
    CHECK(sp.profile == 100 && sp.level == 22 && sp.width == 352 && sp.height == 640);  /* it downsized */
    /* baseline QCIF SPS like our encoder's (profile-level 42 80 0a): 11x9 macroblocks */
    {
        static const u8 q[] = { 0x67, 0x42, 0x80, 0x0a, 0xda, 0x0b, 0x13, 0x90 };
        CHECK(c277_sps_parse(q, sizeof(q), &sp) == 0);
        CHECK(sp.profile == 66 && sp.constraints == 0x80 && sp.level == 10 && sp.width == 176 && sp.height == 144);
    }
    CHECK(c277_sps_parse(p, 3, &sp) != 0);
    CHECK(c277_sps_parse(p + 20, 10, &sp) != 0);
}

static void test_split(void)
{
    static const u8 d[] = { 0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 9, 0, 0, 0, 1, 0x65, 7, 7, 7, 0 };
    c277_nal nl[8];
    int n = c277_annexb_split(d, sizeof(d), nl, 8);
    CHECK(n == 3);
    CHECK(nl[0].off == 4 && nl[0].len == 3);
    CHECK(nl[1].off == 10 && nl[1].len == 2);
    CHECK(nl[2].off == 16 && nl[2].len == 4);
    CHECK(c277_annexb_split(d + 4, 3, nl, 8) == 1 && nl[0].len == 3);   /* no start code: one NAL */
}

/* ---- packetizer */
static u8 sps_nal[] = { 0x67, 0x42, 0x80, 0x0a, 0xda, 0x0b, 0x13, 0x90 };   /* baseline L1.0 QCIF */
static u8 pps_nal[] = { 0x68, 0xce, 0x3c, 0x80 };

static u32 build_unit(u8 *o, int with_ps, int idr, u32 body)
{
    u32 n = 0, i;
    if (with_ps) {
        o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1; memcpy(o + n, sps_nal, sizeof(sps_nal)); n += sizeof(sps_nal);
        o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1; memcpy(o + n, pps_nal, sizeof(pps_nal)); n += sizeof(pps_nal);
    }
    if (body) {
        o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1;
        o[n++] = (u8)(idr ? 0x65 : 0x41);
        for (i = 1; i < body; i++) o[n++] = (u8)(1 + (i * 7 + (idr ? 3 : 5)) % 250);   /* never 0: no start codes */
    }
    return n;
}

typedef struct { u8 d[1500]; int n; } pkt;

static int run_au(c277_vtx *v, pkt *out, int max)
{
    int n = 0, r;
    while (n < max && (r = c277_vtx_next(v, out[n].d, sizeof(out[n].d))) > 0) { out[n].n = r; n++; }
    return n;
}

static void test_packetizer(void)
{
    static const u8 rnd6[6] = { 0x51, 0x23, 0x10, 0x00, 0x00, 0x00 };
    c277_vtx *v = (c277_vtx *)calloc(1, sizeof(*v));
    u8 *unit = (u8 *)malloc(20000);
    pkt *pk = (pkt *)calloc(32, sizeof(pkt));
    u8 re[8000];
    u32 un, rn, i, ts0, seq0;
    int n, k;
    c277_rtp_hdr h;

    c277_vtx_init(v, 4, rnd6);
    /* a P frame before the first IDR is dropped, and params alone are only cached */
    un = build_unit(unit, 0, 0, 300);
    CHECK(c277_vtx_put(v, unit, un, 1000) == C277_VTX_DROPPED);
    un = build_unit(unit, 1, 0, 0);
    CHECK(c277_vtx_put(v, unit, un, 1000) == C277_VTX_PARAMS && v->sps_len == 8 && v->pps_len == 4);
    CHECK(c277_vtx_next(v, pk[0].d, sizeof(pk[0].d)) == 0);

    /* IDR of 4000 bytes in its own unit: STAP-A(SPS,PPS) + FU-A x4, marker on the last */
    un = build_unit(unit, 0, 1, 4000);
    CHECK(c277_vtx_put(v, unit, un, 1000) == C277_VTX_QUEUED);
    n = run_au(v, pk, 32);
    CHECK(n == 1 + 5);                                   /* 3999 bytes / 998 per fragment = 5 */
    CHECK(c277_rtp_parse(pk[0].d, (u32)pk[0].n, &h) == 0);
    CHECK(pk[0].d[0] == 0x90 && pk[0].d[1] == 96 && h.ssrc == 4);
    CHECK(pk[0].d[12] == 0xBE && pk[0].d[13] == 0xDE && pk[0].d[14] == 0 && pk[0].d[15] == 1 &&
          pk[0].d[16] == 0x21 && pk[0].d[19] == 0);       /* same extension layout as the capture */
    CHECK(h.payload[0] == 0x78 && h.plen == 1 + 2 + 8 + 2 + 4);
    CHECK(h.payload[1] == 0 && h.payload[2] == 8 && memcmp(h.payload + 3, sps_nal, 8) == 0);
    CHECK(h.payload[11] == 0 && h.payload[12] == 4 && memcmp(h.payload + 13, pps_nal, 4) == 0);
    seq0 = h.seq; ts0 = h.ts;
    rn = 0;
    for (i = 1; i < (u32)n; i++) {
        c277_rtp_hdr hh;
        u32 body;
        CHECK(c277_rtp_parse(pk[i].d, (u32)pk[i].n, &hh) == 0);
        CHECK(hh.seq == (u16)(seq0 + i) && hh.ts == ts0 && hh.pt == 96);
        CHECK(hh.marker == (i == (u32)n - 1));
        CHECK(hh.plen <= C277_VMTU);
        CHECK(hh.payload[0] == 0x7c);                      /* FU indicator: NRI 3, type 28 */
        CHECK(((hh.payload[1] >> 7) & 1) == (i == 1));     /* S */
        CHECK(((hh.payload[1] >> 6) & 1) == (i == (u32)n - 1));   /* E */
        CHECK((hh.payload[1] & 31) == 5);
        body = hh.plen - 2;
        if (i == 1) re[rn++] = (u8)((hh.payload[0] & 0xE0) | (hh.payload[1] & 31));
        memcpy(re + rn, hh.payload + 2, body); rn += body;
    }
    CHECK(rn == 4000 && memcmp(re, unit + 4, 4000) == 0);   /* FU-A reassembles to the original NAL */

    /* P frame: one single-NAL packet with marker, +66 ms = +5940 ticks, seq continues */
    un = build_unit(unit, 0, 0, 450);
    CHECK(c277_vtx_put(v, unit, un, 1066) == C277_VTX_QUEUED);
    k = run_au(v, pk, 32);
    CHECK(k == 1);
    CHECK(c277_rtp_parse(pk[0].d, (u32)pk[0].n, &h) == 0);
    CHECK(h.marker && h.plen == 450 && h.payload[0] == 0x41 && h.seq == (u16)(seq0 + (u32)n));
    CHECK(h.ts == ts0 + 5940UL);
    /* a second put while one is queued is refused */
    CHECK(c277_vtx_put(v, unit, un, 1070) == C277_VTX_QUEUED);
    CHECK(c277_vtx_put(v, unit, un, 1071) == C277_VTX_DROPPED);
    run_au(v, pk, 32);

    /* camera switch: a rebuilt encoder sends new parameter sets + IDR in one unit: STAP-A
     * carries the NEW SPS, seq/ts stay continuous, SSRC unchanged */
    {
        u32 s1;
        u16 last_seq;
        sps_nal[3] = 0x14; sps_nal[4] = 0xaa;
        un = build_unit(unit, 1, 1, 1500);
        CHECK(c277_vtx_put(v, unit, un, 2000) == C277_VTX_QUEUED);
        n = run_au(v, pk, 32);
        CHECK(n == 3);                                   /* STAP-A, FU-A x2 */
        CHECK(c277_rtp_parse(pk[0].d, (u32)pk[0].n, &h) == 0);
        s1 = h.seq; last_seq = h.seq;
        CHECK(h.ssrc == 4 && h.payload[0] == 0x78 && h.payload[6] == 0x14 && h.payload[7] == 0xaa);
        CHECK(h.ts == ts0 + (2000 - 1000) * 90UL);
        CHECK(c277_rtp_parse(pk[2].d, (u32)pk[2].n, &h) == 0 && h.marker && h.seq == (u16)(last_seq + 2));
        (void)s1;
    }
    /* a 1000 byte NAL is still one packet, 1001 becomes FU-A */
    un = build_unit(unit, 0, 0, 1000);
    CHECK(c277_vtx_put(v, unit, un, 2100) == C277_VTX_QUEUED && run_au(v, pk, 32) == 1);
    un = build_unit(unit, 0, 0, 1001);
    CHECK(c277_vtx_put(v, unit, un, 2166) == C277_VTX_QUEUED && run_au(v, pk, 32) == 2);
    /* off/on: needs a new IDR */
    c277_vtx_reset(v);
    un = build_unit(unit, 0, 0, 300);
    CHECK(c277_vtx_put(v, unit, un, 3000) == C277_VTX_DROPPED);
    /* two VCL NALs in one unit (two slices): marker only on the last */
    {
        u8 *u2 = (u8 *)malloc(4000);
        un = build_unit(u2, 1, 1, 300);
        un += build_unit(u2 + un, 0, 1, 200);
        CHECK(c277_vtx_put(v, u2, un, 3100) == C277_VTX_QUEUED);
        n = run_au(v, pk, 32);
        CHECK(n == 3);
        CHECK(c277_rtp_parse(pk[1].d, (u32)pk[1].n, &h) == 0 && !h.marker && h.plen == 300);
        CHECK(c277_rtp_parse(pk[2].d, (u32)pk[2].n, &h) == 0 && h.marker && h.plen == 200);
        free(u2);
    }
    /* too big / empty */
    CHECK(c277_vtx_put(v, unit, 0, 3200) == C277_VTX_DROPPED);
    CHECK(c277_vtx_put(v, unit, C277_VAU_MAX + 1, 3200) == C277_VTX_DROPPED);
    free(v); free(unit); free(pk);
}

static void test_rtcp(void)
{
    u8 cap[64], mine[64], pli[16], two[64];
    int n;
    c277_rtcp_info ri;
    n = unhex(CAP_SR, cap, sizeof(cap));
    CHECK(n == 44);
    /* our builder reproduces the official app's SR byte for byte (same field values, CNAME "cname") */
    CHECK(c277_rtcp_build_sr(mine, sizeof(mine), 3, 0xeeae2a89UL, 0xf58127b2UL, 0x2a23de30UL, 0, 0) == 44);
    CHECK(memcmp(mine, cap, 44) == 0);
    CHECK(c277_rtcp_build_sr(mine, 43, 3, 0, 0, 0, 0, 0) < 0);
    CHECK(c277_rtcp_parse(cap, 44, 3, &ri) == 0 && ri.n_sr == 1 && ri.n_pli == 0 && ri.n_rr == 0);
    n = unhex(CAP_RR, two, sizeof(two));
    CHECK(c277_rtcp_parse(two, (u32)n, 4, &ri) == 0 && ri.n_rr == 1 && !ri.rr_have);
    /* PLI addressed to our SSRC, alone and behind an RR in a compound packet */
    CHECK(c277_rtcp_build_pli(pli, sizeof(pli), 1, 4) == 12);
    CHECK(c277_rtcp_parse(pli, 12, 4, &ri) == 0 && ri.n_pli == 1 && ri.n_fir == 0);
    CHECK(c277_rtcp_parse(pli, 12, 3, &ri) == 0 && ri.n_pli == 0);        /* for another SSRC */
    n = unhex(CAP_RR, two, sizeof(two));
    memcpy(two + n, pli, 12);
    CHECK(c277_rtcp_parse(two, (u32)n + 12, 4, &ri) == 0 && ri.n_rr == 1 && ri.n_pli == 1);
    /* FIR: PSFB fmt 4 */
    memcpy(mine, "\x84\xce\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x07\x00\x00\x00", 20);
    CHECK(c277_rtcp_parse(mine, 20, 4, &ri) == 0 && ri.n_fir == 1);
    /* NACK (RTPFB fmt 1), transport-cc feedback (fmt 15), REMB (PSFB fmt 15) */
    memcpy(mine, "\x81\xcd\x00\x03\x00\x00\x00\x01\x00\x00\x00\x04\x01\x02\x00\x00", 16);
    CHECK(c277_rtcp_parse(mine, 16, 4, &ri) == 0 && ri.n_nack == 1);
    memcpy(mine, "\x8f\xcd\x00\x02\x00\x00\x00\x01\x00\x00\x00\x04", 12);
    CHECK(c277_rtcp_parse(mine, 12, 4, &ri) == 0 && ri.n_twcc == 1 && ri.n_nack == 0);
    memcpy(mine, "\x8f\xce\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00", 12);
    CHECK(c277_rtcp_parse(mine, 12, 4, &ri) == 0 && ri.n_remb == 1 && ri.n_pli == 0);
    /* RR with one report block about SSRC 4: fraction 12, 345 lost, jitter 77 */
    memset(mine, 0, sizeof(mine));
    mine[0] = 0x81; mine[1] = 201; mine[3] = 7; mine[7] = 1;
    mine[11] = 4; mine[12] = 12; mine[14] = 1; mine[15] = 0x59; mine[27] = 77;
    CHECK(c277_rtcp_parse(mine, 32, 4, &ri) == 0 && ri.rr_have && ri.rr_fraction == 12 && ri.rr_lost == 345 &&
          ri.rr_jitter == 77);
    /* malformed: length beyond the data, wrong version */
    CHECK(c277_rtcp_parse(pli, 8, 4, &ri) < 0);
    pli[0] = 0x01;
    CHECK(c277_rtcp_parse(pli, 12, 4, &ri) < 0);
}


/* ---- receiver: packetize with our own sender, depacketize, with and without loss */
static u32 g_now = 1000;
static int feed(c277_vrx *r, c277_vtx *v, u32 now, int drop_idx, int *got, u8 *copy, u32 *copy_len)
{
    pkt *pk = (pkt *)calloc(32, sizeof(pkt));
    int n = run_au(v, pk, 32), i, ready = 0;
    (void)now;
    for (i = 0; i < n; i++) {
        c277_rtp_hdr h;
        if (i == drop_idx) continue;
        CHECK(c277_rtp_parse(pk[i].d, (u32)pk[i].n, &h) == 0);
        g_now += 5;
        if (c277_vrx_put(r, h.seq, h.ts, h.marker, h.ssrc, h.payload, h.plen, g_now)) {
            ready++;
            if (copy) { memcpy(copy, r->au, r->ready_len); *copy_len = r->ready_len; }
            *got = r->ready_idr;
            c277_vrx_done(r);
        }
    }
    if (drop_idx >= 0 && c277_vrx_tick(r, g_now + 200)) {      /* the wait for the missing packet is over */
        ready++;
        if (copy) { memcpy(copy, r->au, r->ready_len); *copy_len = r->ready_len; }
        *got = r->ready_idr;
        c277_vrx_done(r);
    }
    free(pk);
    return ready;
}

static void test_receiver(void)
{
    static const u8 rnd6[6] = { 0x51, 0x23, 0x10, 0x00, 0x00, 0x00 };
    c277_vtx *v = (c277_vtx *)calloc(1, sizeof(*v));
    c277_vrx *r = (c277_vrx *)calloc(1, sizeof(*r));
    u8 *unit = (u8 *)malloc(20000), *copy = (u8 *)malloc(20000);
    u32 un, cl = 0, fr, lost, hi;
    int idr = 0, n, t;
    u8 buf[32];
    c277_rtcp_info ri;

    c277_vtx_init(v, 4, rnd6);
    c277_vrx_init(r);
    un = build_unit(unit, 1, 0, 0);
    c277_vtx_put(v, unit, un, 1000);
    un = build_unit(unit, 0, 1, 4000);
    CHECK(c277_vtx_put(v, unit, un, 1000) == C277_VTX_QUEUED);
    n = feed(r, v, 1000, -1, &idr, copy, &cl);
    CHECK(n == 1 && idr == 1 && r->need_idr == 0);
    /* parameter sets were sent in the STAP-A: the unit is SPS PPS IDR in Annex-B with 4 byte start codes */
    CHECK(copy[0] == 0 && copy[3] == 1 && copy[4] == 0x67 && copy[12] == 0 && copy[16] == 0x68 && copy[20] == 0 && copy[24] == 0x65);
    CHECK(memcmp(copy + 24, unit + 4, 4000) == 0);
    CHECK(r->sps_len == 8 && r->pps_len == 4 && r->sps_changed == 1);
    /* P frames */
    for (t = 0; t < 4; t++) {
        un = build_unit(unit, 0, 0, 300 + t * 900);
        CHECK(c277_vtx_put(v, unit, un, 1100 + t * 66) == C277_VTX_QUEUED);
        n = feed(r, v, 0, -1, &idr, copy, &cl);
        CHECK(n == 1 && idr == 0 && cl == un);
        CHECK(memcmp(copy, unit, un) == 0);
    }
    CHECK(r->n_au == 5 && r->n_lost == 0 && r->need_pli == 1);   /* the start asked for an IDR */
    r->need_pli = 0;
    /* a lost fragment in a big P frame: the picture is dropped, a PLI is due, P frames are skipped */
    un = build_unit(unit, 0, 0, 3000);
    c277_vtx_put(v, unit, un, 1500);
    n = feed(r, v, 0, 2, &idr, copy, &cl);
    CHECK(n == 0 && r->need_idr == 1 && r->need_pli == 1 && r->n_lost == 1);
    r->need_pli = 0;
    un = build_unit(unit, 0, 0, 400);
    c277_vtx_put(v, unit, un, 1600);
    n = feed(r, v, 0, -1, &idr, copy, &cl);
    CHECK(n == 0 && r->n_wait >= 1);                     /* waiting for an IDR */
    /* the peer answers with an IDR (with parameter sets in a separate STAP-A): decoding resumes */
    un = build_unit(unit, 1, 1, 2500);
    c277_vtx_put(v, unit, un, 1700);
    n = feed(r, v, 0, -1, &idr, copy, &cl);
    CHECK(n == 1 && idr == 1 && r->need_idr == 0);
    /* stats for the receiver report */
    c277_vrx_stats(r, &fr, &lost, &hi);
    CHECK(lost == 1 && fr > 0 && fr < 256 && (hi & 0xFFFF) == (u32)(r->next_seq - 1));
    c277_vrx_stats(r, &fr, &lost, &hi);
    CHECK(fr == 0);
    /* late duplicate is ignored */
    {
        c277_rtp_hdr h;
        u8 pkt1[64];
        memset(pkt1, 0, sizeof(pkt1));
        pkt1[0] = 0x80; pkt1[1] = 96; pkt1[2] = (u8)((r->next_seq - 5) >> 8); pkt1[3] = (u8)(r->next_seq - 5);
        pkt1[11] = 4; pkt1[12] = 0x41; pkt1[13] = 1;
        CHECK(c277_rtp_parse(pkt1, 14, &h) == 0);
        CHECK(c277_vrx_put(r, h.seq, h.ts, 1, h.ssrc, h.payload, h.plen, g_now) == 0 && r->n_late == 1);
    }
    /* RR and REMB builders, NACK list parse */
    CHECK(c277_rtcp_build_rr(buf, sizeof(buf), 4, 3, 12, 345, 0x10002, 5) == 32);
    CHECK(c277_rtcp_parse(buf, 32, 3, &ri) == 0 && ri.rr_have && ri.rr_fraction == 12 && ri.rr_lost == 345);
    CHECK(c277_rtcp_build_remb(buf, sizeof(buf), 4, 3, 150000) == 24);
    CHECK(buf[1] == 206 && (buf[0] & 31) == 15 && memcmp(buf + 12, "REMB", 4) == 0 && buf[16] == 1 &&
          (((u32)(buf[17] & 3) << 16 | (u32)buf[18] << 8 | buf[19]) << (buf[17] >> 2)) <= 150000 &&
          (((u32)(buf[17] & 3) << 16 | (u32)buf[18] << 8 | buf[19]) << (buf[17] >> 2)) > 149000);
    CHECK(c277_rtcp_parse(buf, 24, 3, &ri) == 0 && ri.n_remb == 1);
    memcpy(buf, "\x81\xcd\x00\x03\x00\x00\x00\x01\x00\x00\x00\x04\x01\x02\x00\x05", 16);   /* pid 258, blp bits 0 and 2 */
    CHECK(c277_rtcp_parse(buf, 16, 4, &ri) == 0 && ri.n_nack_seq == 3 && ri.nack_seq[0] == 258 &&
          ri.nack_seq[1] == 259 && ri.nack_seq[2] == 261);
    free(v); free(r); free(unit); free(copy);
}

/* ---- reordering: swapped packets survive, a late retransmission fills a gap, a real loss times out */
static void test_reorder(void)
{
    static const u8 rnd6[6] = { 0x51, 0x23, 0x10, 0x00, 0x00, 0x00 };
    c277_vtx *v = (c277_vtx *)calloc(1, sizeof(*v));
    c277_vrx *r = (c277_vrx *)calloc(1, sizeof(*r));
    u8 *unit = (u8 *)malloc(20000);
    pkt *pk = (pkt *)calloc(32, sizeof(pkt));
    c277_rtp_hdr h[32];
    u32 un, now = 5000;
    int n, i, got = 0;
    u8 b[16];
    c277_rtcp_info ri;

    c277_vtx_init(v, 4, rnd6);
    c277_vrx_init(r);
    un = build_unit(unit, 1, 0, 0);
    c277_vtx_put(v, unit, un, 1000);
    un = build_unit(unit, 0, 1, 5000);                   /* STAP-A + 6 FU-A */
    c277_vtx_put(v, unit, un, 1000);
    n = run_au(v, pk, 32);
    CHECK(n == 7);
    for (i = 0; i < n; i++) CHECK(c277_rtp_parse(pk[i].d, (u32)pk[i].n, &h[i]) == 0);
    /* order 0 2 1 3 4 6 5: a swap in the middle and one at the end */
    {
        static const int ord[7] = { 0, 2, 1, 3, 4, 6, 5 };
        for (i = 0; i < 7; i++) {
            int k = ord[i];
            now += 3;
            if (c277_vrx_put(r, h[k].seq, h[k].ts, h[k].marker, h[k].ssrc, h[k].payload, h[k].plen, now)) got++;
            if (i == 1) CHECK(r->n_nack == 1 && r->nack[0] == h[1].seq);     /* packet 1 is asked for at once */
        }
    }
    CHECK(got == 1 && r->ready_idr == 1 && r->n_lost == 0 && r->n_drop_au == 0 && r->need_idr == 0);
    CHECK(r->n_reordered >= 2);
    c277_vrx_done(r);
    /* a second unit: packet 2 is lost and then arrives late (a retransmission) within the wait */
    c277_vtx_put(v, unit, build_unit(unit, 0, 0, 4500), 1100);
    n = run_au(v, pk, 32);
    for (i = 0; i < n; i++) CHECK(c277_rtp_parse(pk[i].d, (u32)pk[i].n, &h[i]) == 0);
    got = 0;
    for (i = 0; i < n; i++) {
        if (i == 2) continue;
        now += 3;
        if (c277_vrx_put(r, h[i].seq, h[i].ts, h[i].marker, h[i].ssrc, h[i].payload, h[i].plen, now)) got++;
    }
    CHECK(got == 0 && r->n_nack == 1 && r->nack[0] == h[2].seq);
    CHECK(c277_rtcp_build_nack(b, sizeof(b), 4, 3, r->nack[0], 0) == 16);
    CHECK(c277_rtcp_parse(b, 16, 3, &ri) == 0 && ri.n_nack == 1 && ri.nack_seq[0] == h[2].seq);
    now += 20;
    if (c277_vrx_put(r, h[2].seq, h[2].ts, h[2].marker, h[2].ssrc, h[2].payload, h[2].plen, now)) got++;
    CHECK(got == 1 && r->ready_idr == 0 && r->n_lost == 0 && r->need_idr == 0 && r->n_nack == 0);
    c277_vrx_done(r);
    /* the same unit again, but the packet never arrives: after the wait the picture is dropped and a PLI is due */
    c277_vtx_put(v, unit, build_unit(unit, 0, 0, 4500), 1200);
    n = run_au(v, pk, 32);
    for (i = 0; i < n; i++) CHECK(c277_rtp_parse(pk[i].d, (u32)pk[i].n, &h[i]) == 0);
    got = 0;
    for (i = 0; i < n; i++) {
        if (i == 2) continue;
        now += 3;
        if (c277_vrx_put(r, h[i].seq, h[i].ts, h[i].marker, h[i].ssrc, h[i].payload, h[i].plen, now)) got++;
    }
    CHECK(got == 0 && r->need_idr == 0);
    CHECK(c277_vrx_tick(r, now + 20) == 0 && r->need_idr == 0);              /* still waiting */
    CHECK(c277_vrx_tick(r, now + 100) == 0 && r->need_idr == 1 && r->need_pli == 1 && r->n_lost == 1 && r->n_gap_timeout == 1);
    free(v); free(r); free(unit); free(pk);
}

int main(void)
{
    test_sps();
    test_split();
    test_packetizer();
    test_rtcp();
    test_receiver();
    test_reorder();
    printf("test_video: %d checks, %d failed\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
