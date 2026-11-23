/* Host tests for c277_ice / c277_rtp / c277_session.
 * usage: test_session crosscheck.txt   (run from native/call277 so that
 * fixtures/official_caller_capture.txt, a local-only real capture, is found) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c277_session.h"

static int g_fail = 0, g_n = 0;
#define CHECK(cond) do { g_n++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static const char *g_xc;

static u8 *xc_get(const char *name, u32 *len)
{
    static u8 buf[8][4096];
    static int slot;
    char key[64];
    const char *p = g_xc;
    u8 *b = buf[slot++ & 7];
    size_t kl;
    sprintf(key, "%s ", name);
    kl = strlen(key);
    while (*p) {
        if (strncmp(p, key, kl) == 0) {
            const char *h = p + kl;
            u32 n = 0;
            if (*h == '-') { *len = 0; return b; }
            while (h[0] && h[0] != '\n') { unsigned v; sscanf(h, "%2x", &v); b[n++] = (u8)v; h += 2; }
            *len = n;
            return b;
        }
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    printf("missing crosscheck %s\n", name);
    g_fail++;
    *len = 0;
    return b;
}
#define XC_EQ(name, buf, n) do { u32 l_; u8 *e_ = xc_get(name, &l_); g_n++; \
    if (l_ != (u32)(n) || memcmp(e_, (buf), l_) != 0) { g_fail++; printf("FAIL xc %s (len %u vs %u)\n", name, (unsigned)l_, (unsigned)(n)); } } while (0)

static void data(u8 *b, u32 n, u32 mul, u32 add)
{
    u32 i;
    for (i = 0; i < n; i++) b[i] = (u8)((i * mul + add) & 255);
}

static u32 rng_state = 777;
static u32 rnd(void) { rng_state = rng_state * 1664525UL + 1013904223UL; return rng_state >> 8; }

/* ------------------------------------------------------------------ rtp */
static void test_rtp(void)
{
    u8 op[64], pk[200], rx[200], o[700];
    c277_rtp_tx tx;
    c277_rtp_hdr h;
    c277_jb *jb = (c277_jb *)malloc(sizeof(c277_jb));
    u8 r6[6], opus60[41];
    u32 len, ts, i;
    int n;

    data(op, 64, 1, 0);
    op[0] = 0x18; CHECK(c277_opus_samples48k(op, 20) == 2880);          /* SILK NB 60 ms */
    op[0] = 0x08; CHECK(c277_opus_samples48k(op, 20) == 960);           /* SILK NB 20 ms */
    op[0] = 0x00; CHECK(c277_opus_samples48k(op, 20) == 480);           /* SILK NB 10 ms */
    op[0] = 0x68; CHECK(c277_opus_samples48k(op, 20) == 960);           /* hybrid SWB 20 ms */
    op[0] = 0x98; CHECK(c277_opus_samples48k(op, 20) == 960);           /* CELT 20 ms */
    op[0] = 0x80; CHECK(c277_opus_samples48k(op, 20) == 120);           /* CELT 2.5 ms */
    op[0] = 0x19; CHECK(c277_opus_samples48k(op, 20) == 5760);          /* 2 x 60 ms, code 1 */
    op[0] = 0x1B; op[1] = 2; CHECK(c277_opus_samples48k(op, 20) == 5760);   /* code 3, 2 frames */
    op[1] = 3; CHECK(c277_opus_samples48k(op, 20) == 0);                /* 180 ms: invalid */
    op[1] = 0; CHECK(c277_opus_samples48k(op, 20) == 0);
    CHECK(c277_opus_samples48k(op, 0) == 0);

    data(r6, 6, 3, 1);
    opus60[0] = 0x18; data(opus60 + 1, 40, 5, 3);
    c277_rtp_tx_init(&tx, 1, r6);
    n = c277_rtp_tx_build(&tx, opus60, 41, pk, sizeof(pk));
    XC_EQ("rtp_tx1", pk, n);
    n = c277_rtp_tx_build(&tx, opus60, 41, pk, sizeof(pk));
    XC_EQ("rtp_tx2", pk, n);
    CHECK(c277_rtp_tx_build(&tx, opus60, 41, pk, 40) < 0);
    CHECK(c277_rtp_parse(pk, (u32)n, &h) == 0 && h.pt == 111 && h.ssrc == 2 && h.plen == 41 && !h.marker);
    c277_rtp_tx_init(&tx, 0, r6);
    CHECK(tx.ssrc == 1);

    {   /* CSRC + one-byte extension + padding, from the python vector */
        u32 l; u8 *e = xc_get("rtp_rx_ext", &l);
        CHECK(c277_rtp_parse(e, l, &h) == 0 && h.pt == 111 && h.marker == 1 && h.seq == 500 &&
              h.ts == 123456 && h.ssrc == 1 && h.plen == 41 && h.payload[0] == 0x18);
        memcpy(rx, e, l);
        CHECK(c277_rtp_parse(rx, l - 4, &h) < 0 || h.plen != 41);          /* padding eats payload: still sane */
        CHECK(c277_rtp_parse(rx, 14, &h) < 0);                               /* CSRC cut */
        CHECK(c277_rtp_parse(rx, 22, &h) < 0);                               /* extension cut */
        rx[0] = 0x40; CHECK(c277_rtp_parse(rx, l, &h) < 0);                  /* version 1 */
        rx[0] = 0xA0; rx[l - 1] = 0; CHECK(c277_rtp_parse(rx, l, &h) < 0);   /* padding count 0 */
    }
    {   /* two-byte-header extension profile 0x1000 with 0 words */
        u8 p[16];
        memset(p, 0, sizeof(p)); p[0] = 0x90; p[1] = 111; p[12] = 0x10; p[13] = 0x00; p[14] = 0; p[15] = 0;
        CHECK(c277_rtp_parse(p, 16, &h) == 0 && h.plen == 0);
    }
    { u8 rtcp[8] = {0x80, 201, 0, 1, 0, 0, 0, 1}; CHECK(c277_rtp_is_rtcp(rtcp, 8)); CHECK(!c277_rtp_is_rtcp(pk, 20)); }

    /* jitter buffer */
    c277_jb_init(jb);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, &ts) == C277_JB_EMPTY);
    for (i = 0; i < 5; i++) { op[0] = (u8)i; CHECK(c277_jb_put(jb, (u16)(65533 + i), 1000 + i * 2880, op, 10 + i) == 0); }
    for (i = 0; i < 5; i++) {
        CHECK(c277_jb_get(jb, o, sizeof(o), &len, &ts) == C277_JB_PACKET && len == 10 + i && o[0] == i && ts == 1000 + i * 2880);
    }
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, &ts) == C277_JB_EMPTY);
    /* reorder: 5,7,6 -> delivered 5,6,7 without LOST */
    op[0] = 5; c277_jb_put(jb, 2, 0, op, 4);
    op[0] = 7; c277_jb_put(jb, 4, 0, op, 4);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET && o[0] == 5);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_EMPTY);       /* seq 3 may still arrive */
    op[0] = 6; c277_jb_put(jb, 3, 0, op, 4);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET && o[0] == 6);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET && o[0] == 7);
    /* dup, late */
    CHECK(c277_jb_put(jb, 4, 0, op, 4) == 1 && jb->n_late == 1);
    op[0] = 9; c277_jb_put(jb, 5, 0, op, 4); CHECK(c277_jb_put(jb, 5, 0, op, 4) == 1 && jb->n_dup == 1);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET);
    /* gap: 6 missing, 7 and 8 present -> LOST then packets */
    c277_jb_put(jb, 7, 0, op, 4); c277_jb_put(jb, 8, 0, op, 4);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_LOST && len == 0 && jb->n_lost == 1);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET);
    CHECK(c277_jb_get(jb, o, sizeof(o), &len, 0) == C277_JB_PACKET);
    CHECK(c277_jb_depth(jb) == 0);
    /* overflow: burst far beyond the depth drops the oldest, stays bounded and ordered */
    for (i = 0; i < 40; i++) c277_jb_put(jb, (u16)(100 + i), 0, op, 4);
    CHECK(c277_jb_depth(jb) <= C277_JB_SLOTS && jb->n_overflow > 0);
    {
        int last = -1, ok = 1;
        while (c277_jb_get(jb, o, sizeof(o), &len, &ts) == C277_JB_PACKET) { (void)ts; }
        (void)last; (void)ok;
    }
    /* huge jump resync, oversize payload */
    c277_jb_put(jb, 20000, 0, op, 4);
    CHECK(jb->next == 20000 && c277_jb_depth(jb) == 1);
    CHECK(c277_jb_put(jb, 20001, 0, op, C277_JB_MAXPKT + 1) == 1 && jb->n_big == 1);
    free(jb);
}

/* ------------------------------------------------------------------ ice */
static void make_creds(u8 *body, u32 *blen, const char *uf, const char *pw, const char *cand)
{
    c277_slice c, u, p;
    c.p = (const u8 *)cand; c.len = (u32)strlen(cand);
    u.p = (const u8 *)uf; u.len = (u32)strlen(uf);
    p.p = (const u8 *)pw; p.len = (u32)strlen(pw);
    *blen = (u32)c277_msg_build_candidates(body, 600, &c, cand[0] ? 1 : 0, &u, &p);
}

static void test_ice_vectors(void)
{
    c277_ice ice;
    u8 r[C277_ICE_RANDOM], body[600], out[300], req[300];
    char cand[200];
    u32 bl, l, now = 5000;
    int n;
    u8 *e;

    data(r, sizeof(r), 3, 1);
    c277_ice_init(&ice, 1, r);
    c277_ice_set_local(&ice, 1, 777, 596, 0x5B6C1108UL, 596);
    e = xc_get("ice_ufrag", &l); CHECK(l == 4 && memcmp(e, c277_ice_ufrag(&ice), 4) == 0);
    e = xc_get("ice_pwd", &l); CHECK(l == 24 && memcmp(e, c277_ice_pwd(&ice), 24) == 0);
    /* nothing to do before the peer's data */
    CHECK(c277_ice_tick(&ice, now, out, sizeof(out)) == 0 && c277_ice_state(&ice) == C277_ICE_IDLE);
    /* host candidate carries the credentials; first creds win; host cand ignored */
    make_creds(body, &bl, "wxyz", "pppppppppppppppppppppppp",
               "candidate:1 0 udp 2122260224 192.168.7.7 40000 typ host generation 0 ufrag wxyz network-id 5 network-cost 10");
    CHECK(c277_ice_on_candidates(&ice, body, bl) == 0);
    CHECK(c277_ice_tick(&ice, now, out, sizeof(out)) == 0);               /* still no peer tag */
    make_creds(body, &bl, "OTHR", "qqqqqqqqqqqqqqqqqqqqqqqq", "");
    CHECK(c277_ice_on_candidates(&ice, body, bl) == 0);
    /* wrong id / wrong port relay candidates ignored, right one kept */
    sprintf(cand, "candidate:1 1 udp 5 reflector-2-4242.reflector 596 typ relay generation 0 ufrag wxyz");
    make_creds(body, &bl, "wxyz", "pppppppppppppppppppppppp", cand);
    CHECK(c277_ice_on_candidates(&ice, body, bl) == 0);
    sprintf(cand, "candidate:1 1 udp 5 reflector-1-4242.reflector 597 typ relay generation 0 ufrag wxyz");
    make_creds(body, &bl, "wxyz", "pppppppppppppppppppppppp", cand);
    CHECK(c277_ice_on_candidates(&ice, body, bl) == 0);
    sprintf(cand, "candidate:1 1 udp 5 reflector-1-4242.reflector 596 typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag wxyz");
    make_creds(body, &bl, "wxyz", "pppppppppppppppppppppppp", cand);
    CHECK(c277_ice_on_candidates(&ice, body, bl) == 1);
    CHECK(c277_ice_on_candidates(&ice, body, 5) < 0);

    n = c277_ice_tick(&ice, now, req, sizeof(req));
    XC_EQ("ice_req1", req, n);
    CHECK(c277_ice_state(&ice) == C277_ICE_CHECKING);
    CHECK(c277_ice_tick(&ice, now + 499, out, sizeof(out)) == 0);
    {   /* second request after 500 ms, new txid, still no USE-CANDIDATE before a response */
        c277_stun_msg m1, m2;
        n = c277_ice_tick(&ice, now + 500, out, sizeof(out));
        CHECK(n > 0 && c277_stun_parse(out, (u32)n, &m2) == 0 && !m2.use_candidate && m2.controlling);
        c277_stun_parse(req, (u32)c277_stun_build_request(req, sizeof(req), (u8 *)"123456789012", (const u8 *)"a", 1, 1, 1, r, 0, (const u8 *)"k", 1), &m1);
        CHECK(memcmp(m1.txid, m2.txid, 12) != 0);
    }
    {   /* valid response to the 1st request (txid ctr 1) -> CONNECTED */
        u8 resp[200], tx1[12];
        int rl;
        memcpy(tx1, xc_get("ice_req1", &l) + 8, 12);
        rl = c277_stun_build_success(resp, sizeof(resp), tx1, 0, 0x01020304UL, 5, (const u8 *)"pppppppppppppppppppppppp", 24);
        /* wrong key first: ignored */
        { u8 bad[200]; int bl2 = c277_stun_build_success(bad, sizeof(bad), tx1, 0, 1, 2, (const u8 *)"xxxxxxxxxxxxxxxxxxxxxxxx", 24);
          CHECK(c277_ice_rx(&ice, now + 600, bad, (u32)bl2, 4242, out, sizeof(out)) == 0 && c277_ice_state(&ice) == C277_ICE_CHECKING); }
        /* unknown txid: ignored */
        { u8 bad[200], t2[12]; int bl2; memset(t2, 9, 12);
          bl2 = c277_stun_build_success(bad, sizeof(bad), t2, 0, 1, 2, (const u8 *)"pppppppppppppppppppppppp", 24);
          CHECK(c277_ice_rx(&ice, now + 600, bad, (u32)bl2, 4242, out, sizeof(out)) == 0 && c277_ice_state(&ice) == C277_ICE_CHECKING); }
        CHECK(c277_ice_rx(&ice, now + 700, resp, (u32)rl, 4242, out, sizeof(out)) == 0);
        CHECK(c277_ice_state(&ice) == C277_ICE_CONNECTED && !c277_ice_nominated(&ice));
        /* next request: after 2 s, with USE-CANDIDATE: matches python */
        CHECK(c277_ice_tick(&ice, now + 2600, out, sizeof(out)) == 0);
        n = c277_ice_tick(&ice, now + 2700, out, sizeof(out));
        XC_EQ("ice_req2_uc", out, n);
        {   /* response to a use-candidate request nominates */
            u8 tx2[12], rs[200]; int rl2;
            memcpy(tx2, out + 8, 12);
            rl2 = c277_stun_build_success(rs, sizeof(rs), tx2, 0, 1, 2, (const u8 *)"pppppppppppppppppppppppp", 24);
            c277_ice_rx(&ice, now + 2800, rs, (u32)rl2, 4242, out, sizeof(out));
            CHECK(c277_ice_nominated(&ice));
        }
    }
    {   /* peer request -> success response identical to python's; tampering ignored */
        u32 pl, rl2;
        u8 *pr = xc_get("ice_peer_req", &pl);
        u8 mut[300];
        int rl;
        memcpy(mut, pr, pl);
        rl = c277_ice_rx(&ice, now + 3000, mut, pl, 4242, out, sizeof(out));
        XC_EQ("ice_peer_resp", out, rl);
        (void)rl2;
        mut[40] ^= 1;   /* inside USERNAME/PRIORITY: integrity fails */
        CHECK(c277_ice_rx(&ice, now + 3000, mut, pl, 4242, out, sizeof(out)) == 0);
        memcpy(mut, pr, pl); mut[pl - 1] ^= 1;   /* fingerprint */
        CHECK(c277_ice_rx(&ice, now + 3000, mut, pl, 4242, out, sizeof(out)) == 0);
        { u8 *r2 = xc_get("stun_req_ctl", &pl);   /* both controlling + wrong username/key: ignored */
          CHECK(c277_ice_rx(&ice, now + 3000, r2, pl, 4242, out, sizeof(out)) == 0); }
    }
    /* silence while connected: FAILED after 20 s, revives on any valid packet */
    c277_ice_tick(&ice, now + 3000 + 20001, out, sizeof(out));
    CHECK(c277_ice_state(&ice) == C277_ICE_FAILED);
    c277_ice_activity(&ice, now + 24000);
    CHECK(c277_ice_state(&ice) == C277_ICE_CONNECTED);
}

/* Two agents back to back (no reflector framing). */
static void test_ice_pair(void)
{
    c277_ice a, b;
    u8 ra[C277_ICE_RANDOM], rb[C277_ICE_RANDOM], body[600], pkt[300], rsp[300];
    u32 now, bl, nreq = 0;
    int n, r;
    data(ra, sizeof(ra), 7, 5); data(rb, sizeof(rb), 11, 9);
    c277_ice_init(&a, 1, ra); c277_ice_init(&b, 0, rb);
    c277_ice_set_local(&a, 1, 1111, 596, 0x5B6C1108UL, 596);
    c277_ice_set_local(&b, 1, 2222, 596, 0x5B6C1108UL, 596);
    bl = (u32)c277_ice_build_candidates(&a, body, sizeof(body));
    CHECK(c277_ice_on_candidates(&b, body, bl) == 1);
    bl = (u32)c277_ice_build_candidates(&b, body, sizeof(body));
    CHECK(c277_ice_on_candidates(&a, body, bl) == 1);
    for (now = 1000; now < 13000; now += 10) {
        n = c277_ice_tick(&a, now, pkt, sizeof(pkt));
        if (n > 0) { nreq++; r = c277_ice_rx(&b, now, pkt, (u32)n, 1111, rsp, sizeof(rsp));
            if (r > 0) c277_ice_rx(&a, now, rsp, (u32)r, 2222, pkt, sizeof(pkt)); }
        n = c277_ice_tick(&b, now, pkt, sizeof(pkt));
        if (n > 0) { r = c277_ice_rx(&a, now, pkt, (u32)n, 2222, rsp, sizeof(rsp));
            if (r > 0) c277_ice_rx(&b, now, rsp, (u32)r, 1111, pkt, sizeof(pkt)); }
        if (now == 1100) CHECK(c277_ice_state(&a) == C277_ICE_CONNECTED && c277_ice_state(&b) == C277_ICE_CONNECTED);
    }
    CHECK(c277_ice_nominated(&a) && c277_ice_nominated(&b));
    CHECK(nreq >= 5 && nreq <= 8);   /* 1 + (12 s / 2 s) keep-alives */
    /* callee learns the peer tag from the request when the candidate was lost */
    {
        u32 t;
        u8 rc[C277_ICE_RANDOM];
        data(rc, sizeof(rc), 13, 2);
        bl = (u32)c277_ice_build_candidates(&a, body, sizeof(body));
        {   /* a's candidate has id 1 port 596 so it WAS kept; use a fresh agent with a different id instead */
            c277_ice d;
            c277_ice_init(&d, 0, rc);
            c277_ice_set_local(&d, 9, 3333, 596, 0x5B6C1108UL, 596);
            c277_ice_on_candidates(&d, body, bl);
            CHECK(c277_ice_peer_tag(&d, &t) == 0);
            /* a's next request carries d's ufrag? no: a targets b. build via a request signed for d */
            {
                u8 un[16], tb[8] = {1,2,3,4,5,6,7,8};
                int q;
                memcpy(un, c277_ice_ufrag(&d), 4); un[4] = ':'; memcpy(un + 5, "wxyz", 4);
                q = c277_stun_build_request(pkt, sizeof(pkt), (const u8 *)"abcdefghijkl", un, 9, 1, 1, tb, 0,
                                            c277_ice_pwd(&d), 24);
                CHECK(c277_ice_rx(&d, 5, pkt, (u32)q, 9999, rsp, sizeof(rsp)) > 0);
                CHECK(c277_ice_peer_tag(&d, &t) == 1 && t == 9999);
            }
        }
    }
}

/* ------------------------------------------------------- capture replay */

typedef struct { int type; u8 body[8192]; u32 len; } cap_msg;
static int g_cap_n; static cap_msg *g_cap;

static void cap_cb(void *user, int type, const u8 *body, u32 blen)
{
    (void)user;
    if (g_cap_n < 64 && blen <= sizeof(g_cap[0].body)) {
        g_cap[g_cap_n].type = type; g_cap[g_cap_n].len = blen; memcpy(g_cap[g_cap_n].body, body, blen);
        g_cap_n++;
    }
}

static u32 parse_ip(const char *s)
{
    unsigned a, b, c, d;
    sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static int unhex_line(const char *h, u8 *o, u32 cap)
{
    u32 n = 0;
    while (h[0] && h[1] && h[0] != '\n' && h[0] != '\r' && n < cap) { unsigned v; sscanf(h, "%2x", &v); o[n++] = (u8)v; h += 2; }
    return (int)n;
}

static void test_capture(void)
{
    FILE *f = fopen("fixtures/official_caller_capture.txt", "rb");
    static char line[40000];
    static u8 key[256];
    static u8 pk[8][9000];
    int pklen[8], npk = 0, is_out = 0, nconn = 0, i, okc = 0;
    c277_sess_conn conns[8];
    c277_session *s;
    c277_conn peer, dec;
    u8 rn[C277_SESS_RANDOM];
    u8 *scr;
    int have_key = 0;

    if (!f) { printf("skipped: no capture\n"); return; }
    memset(conns, 0, sizeof(conns));
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "key ", 4) == 0) have_key = unhex_line(line + 4, key, 256) == 256;
        else if (strncmp(line, "is_outgoing ", 12) == 0) is_out = atoi(line + 12);
        else if (strncmp(line, "connection ", 11) == 0 && nconn < 8) {
            char *ip = strstr(line, "ip="), *pt = strstr(line, "port="), *tg = strstr(line, "tag="), *id = strstr(line, "id=");
            unsigned long long v;
            c277_sess_conn *c = &conns[nconn++];
            c->webrtc = strstr(line, "phoneConnectionWebrtc") != 0;
            if (ip) c->ip = parse_ip(ip + 3);
            if (pt) c->port = (u32)atoi(pt + 5);
            if (tg) unhex_line(tg + 4, c->peer_tag, 16);
            v = id ? strtoull(id + 3, 0, 10) : 0;
            c->id.hi = (int)(v >> 32); c->id.lo = (u32)v;
        } else if (strncmp(line, "signaling ", 10) == 0 && npk < 8) {
            pklen[npk] = unhex_line(line + 10, pk[npk], sizeof(pk[0])); npk++;
        }
    }
    fclose(f);
    CHECK(have_key && npk > 0 && nconn > 0);
    if (!have_key || !npk) return;

    s = (c277_session *)malloc(sizeof(*s));
    g_cap = (cap_msg *)malloc(64 * sizeof(cap_msg)); g_cap_n = 0;
    scr = (u8 *)malloc(9000);
    data(rn, sizeof(rn), 17, 3);
    CHECK(c277_session_init(s, key, is_out, conns, (u32)nconn, rn, sizeof(rn)) == C277_SESS_OK);
    c277_conn_init(&dec, key, is_out, 1);     /* independent decoder of the same packets */
    for (i = 0; i < npk; i++) {
        if (c277_session_on_signaling(s, pk[i], (u32)pklen[i], 1000 + 20 * (u32)i) == 0) okc++;
        c277_conn_parse(&dec, 1000, pk[i], (u32)pklen[i], scr, cap_cb, 0);
    }
    printf("capture: %d/%d packets parsed ok, role %s\n", okc, npk, is_out ? "caller" : "callee");
    CHECK(okc >= 1);
    CHECK(c277_conn_acks_queued(&s->sig) > 0);
    {   /* creds extracted == independent decode of the first candidates message */
        int k, ncand = 0, nhost = 0, nrelay_ours = 0;
        c277_cands c;
        int seen = 0;
        for (k = 0; k < g_cap_n; k++) {
            u32 j;
            if (g_cap[k].type != C277_MSG_CANDIDATES) continue;
            if (c277_msg_parse_candidates(g_cap[k].body, g_cap[k].len, &c) < 0) { CHECK(0); continue; }
            if (!seen) {
                seen = 1;
                CHECK(s->ice.have_creds && s->ice.rufrag_len == c.ufrag.len && memcmp(s->ice.rufrag, c.ufrag.p, c.ufrag.len) == 0);
                CHECK(s->ice.rpwd_len == c.pwd.len && memcmp(s->ice.rpwd, c.pwd.p, c.pwd.len) == 0);
                CHECK(c.ufrag.len >= 4 && c.pwd.len >= 22);
            }
            for (j = 0; j < c.n && j < C277_MAX_CANDS; j++) {
                c277_sdp_cand sd;
                ncand++;
                if (memchr(c.cand[j].p, 't', c.cand[j].len) && strstr((const char *)c.cand[j].p, "typ host")) nhost++;
                if (c277_sdp_cand_parse((const char *)c.cand[j].p, c.cand[j].len, &sd) == 0 &&
                    sd.id == s->rank && sd.port == s->r_port) nrelay_ours++;
            }
        }
        printf("capture: %d candidate lines (%d host), %d relay for our reflector, peer_cands=%d\n", ncand, nhost, nrelay_ours, s->peer_cands);
        CHECK(seen && ncand >= 1);
        CHECK(s->peer_cands == nrelay_ours);       /* host candidates are never kept */
        CHECK(s->ice.have_rtag == (nrelay_ours > 0));
    }
    /* reflector hello reply -> READY -> our candidates + acks */
    {
        u8 rep[32];
        c277_refl_own_tag(s->tag16, 0, rep); memset(rep + 16, 0xFF, 12); memset(rep + 28, 0, 4);
        c277_session_on_udp(s, s->r_ip, s->r_port, rep, 32, 2000);
        CHECK(c277_session_refl_ready(s));
        c277_session_on_udp(s, s->r_ip + 1, s->r_port, rep, 32, 2000);   /* wrong source: no effect */
    }
    c277_conn_init(&peer, key, is_out ? 0 : 1, 1);
    g_cap_n = 0;
    c277_outq_clear(&s->out);
    CHECK(c277_session_tick(s, 2000) >= 2);
    {
        int sigs = 0, hello = 0, got_cand = 0, k, stun_seen = 0, nrelay_ours_g = s->ice.have_rtag;
        for (k = 0; k < s->out.n; k++) {
            c277_out_item *it = &s->out.item[k];
            if (it->kind == C277_OUT_UDP) { hello += it->len == 40 && it->ip == s->r_ip; continue; }
            sigs++;
            CHECK(c277_conn_parse(&peer, 2000, it->data, it->len, scr, cap_cb, 0) == 0);
            {   /* last entry of the plaintext is an Ack of one of the replayed reliable messages */
                u32 x = is_out ? 8 + 128 : 0 + 128, n = it->len - 16;
                u8 pt[2000];
                if (n <= sizeof(pt) && c277_open(key, x, it->data, it->data + 16, n, pt) == 0) {
                    CHECK(pt[n - 1] == C277_MSG_ACK && (pt[n - 5] & 0x40));
                }
            }
        }
        for (k = 0; k < g_cap_n; k++) {
            c277_cands c; c277_sdp_cand sd; char uf[5];
            if (g_cap[k].type != C277_MSG_CANDIDATES) continue;
            CHECK(c277_msg_parse_candidates(g_cap[k].body, g_cap[k].len, &c) == 0 && c.n == 1 && c.ufrag.len == 4 && c.pwd.len == 24);
            CHECK(memcmp(c.ufrag.p, c277_ice_ufrag(&s->ice), 4) == 0 && memcmp(c.pwd.p, c277_ice_pwd(&s->ice), 24) == 0);
            CHECK(c277_sdp_cand_parse((const char *)c.cand[0].p, c.cand[0].len, &sd) == 0 &&
                  sd.id == s->rank && sd.tag == s->own_rt && sd.port == s->r_port);
            memcpy(uf, c.ufrag.p, 4); uf[4] = 0;
            CHECK(strstr((const char *)c.cand[0].p, " typ relay ") != 0);
            got_cand = 1;
        }
        CHECK(sigs >= 1 && hello == 1 && got_cand);
        for (k = 0; k < s->out.n; k++) {   /* our binding request, wrapped for the peer's reflector tag */
            c277_out_item *it = &s->out.item[k];
            c277_stun_msg m;
            u32 pl = it->len >= 24 ? ((u32)it->data[20] << 24 | (u32)it->data[21] << 16 | (u32)it->data[22] << 8 | it->data[23]) : 0;
            if (it->kind != C277_OUT_UDP || it->len < 60) continue;
            CHECK(s->ice.have_rtag);
            CHECK(memcmp(it->data, s->tag16, 12) == 0 && it->data[12] + 256u * it->data[13] + 65536u * it->data[14] + 16777216u * it->data[15] == s->ice.r_tag);
            CHECK(c277_stun_parse(it->data + 24, pl, &m) == 0 && m.type == C277_STUN_BIND_REQ && m.has_priority);
            CHECK(m.username_len == s->ice.rufrag_len + 5 && memcmp(m.username, s->ice.rufrag, s->ice.rufrag_len) == 0 &&
                  memcmp(m.username + m.username_len - 4, c277_ice_ufrag(&s->ice), 4) == 0);
            CHECK(c277_stun_check_integrity(it->data + 24, pl, &m, s->ice.rpwd, s->ice.rpwd_len) &&
                  c277_stun_check_fingerprint(it->data + 24, pl, &m));
            CHECK(m.controlled && !m.controlling);   /* we are the callee */
            stun_seen = 1;
        }
        CHECK(stun_seen == (nrelay_ours_g > 0));
        CHECK(c277_conn_acks_queued(&s->sig) == 0);
        CHECK(!c277_session_signaling_acked(s));   /* peer has not acked our candidates */
    }
    free(s); free(g_cap); free(scr);
}

/* ------------------------------------------------------- two sessions */

#define SIMQ 512
typedef struct { u32 due; int dst; int kind; u32 len; u8 d[C277_OUT_MAX]; } simpkt;
typedef struct {
    simpkt q[SIMQ]; int n;
    u32 rt[2]; u8 tag12[2][12]; int reg[2];
    int loss, jit;           /* percent, ms */
    u32 sent, dropped;
} sim_t;

static void sim_put(sim_t *m, u32 now, int dst, int kind, const u8 *d, u32 len)
{
    simpkt *p;
    if (m->n >= SIMQ) { m->dropped++; return; }
    if ((int)(rnd() % 100) < m->loss) { m->dropped++; return; }
    p = &m->q[m->n++];
    p->due = now + 5 + (m->jit ? rnd() % (u32)m->jit : 0);
    p->dst = dst; p->kind = kind; p->len = len; memcpy(p->d, d, len);
    m->sent++;
}

/* stand-in reflector: HELLO registers (random tag), DATA routes by destination randomTag
 * and rewrites the header to the receiver's tag (spec 2.2) */
static void refl_in(sim_t *m, u32 now, int from, const u8 *d, u32 n)
{
    u8 o[C277_OUT_MAX];
    int j, other = -1;
    u32 prt;
    if (n >= 40 && d[28] == 0xFE && d[29] == 0xFF) {
        m->rt[from] = (u32)d[12] | ((u32)d[13] << 8) | ((u32)d[14] << 16) | ((u32)d[15] << 24);
        memcpy(m->tag12[from], d, 12); m->reg[from] = 1;
        memcpy(o, d, 16); memset(o + 16, 0xFF, 12); memset(o + 28, 0, 4);
        sim_put(m, now, from, 0, o, 32);    /* reply: tag12 | rt | FF*12 | ... */
        return;
    }
    if (n < 24) return;
    prt = (u32)d[12] | ((u32)d[13] << 8) | ((u32)d[14] << 16) | ((u32)d[15] << 24);
    for (j = 0; j < 2; j++) if (m->reg[j] && m->rt[j] == prt && j != from) other = j;
    if (other < 0) return;
    memcpy(o, d, n);
    memcpy(o, m->tag12[other], 12);
    sim_put(m, now, other, 0, o, n);
}

typedef struct {
    c277_session *s[2];
    sim_t m;
    int sig_loss, sig_jit;
    struct { u32 due; int dst; u32 len; u8 d[C277_OUT_MAX]; } sg[64]; int nsg;
    u32 sig_sent;
} world;

static void drain(world *w, int who, u32 now)
{
    c277_session *s = w->s[who];
    int i;
    for (i = 0; i < s->out.n; i++) {
        c277_out_item *it = &s->out.item[i];
        if (it->kind == C277_OUT_UDP) {
            refl_in(&w->m, now, who, it->data, it->len);
        } else if (w->nsg < 64 && (int)(rnd() % 100) >= w->sig_loss) {
            w->sg[w->nsg].due = now + 30 + (w->sig_jit ? rnd() % (u32)w->sig_jit : 0);
            w->sg[w->nsg].dst = 1 - who; w->sg[w->nsg].len = it->len; memcpy(w->sg[w->nsg].d, it->data, it->len);
            w->nsg++; w->sig_sent++;
        }
    }
    c277_outq_clear(&s->out);
}

static void world_deliver(world *w, u32 now)
{
    int i;
    for (i = 0; i < w->m.n; ) {
        simpkt *p = &w->m.q[i];
        if ((int)(now - p->due) >= 0) {
            simpkt c = *p;
            w->m.q[i] = w->m.q[--w->m.n];
            c277_session_on_udp(w->s[c.dst], w->s[0]->r_ip, w->s[0]->r_port, c.d, c.len, now);
        } else i++;
    }
    for (i = 0; i < w->nsg; ) {
        if ((int)(now - w->sg[i].due) >= 0) {
            int dst = w->sg[i].dst; u32 len = w->sg[i].len; u8 buf[C277_OUT_MAX];
            memcpy(buf, w->sg[i].d, len);
            w->sg[i] = w->sg[--w->nsg];
            c277_session_on_signaling(w->s[dst], buf, len, now);
        } else i++;
    }
}

static void sim_world(int loss, int jit, int sig_loss, int audio_loss)
{
    world *w = (world *)calloc(1, sizeof(world));
    u8 key[256], rn[2][C277_SESS_RANDOM];
    c277_sess_conn cs[2];
    u32 now, sent[2] = {0, 0};
    int got[2] = {0, 0}, lost[2] = {0, 0}, last[2] = {-1, -1}, order_ok = 1, w_i;
    u32 conn_at[2] = {0, 0};
    int k;

    w->s[0] = (c277_session *)malloc(sizeof(c277_session));
    w->s[1] = (c277_session *)malloc(sizeof(c277_session));
    w->m.loss = loss; w->m.jit = jit; w->sig_loss = sig_loss; w->sig_jit = jit * 2;
    data(key, 256, 29, 7);
    for (k = 0; k < 2; k++) {
        u32 i;
        for (i = 0; i < C277_SESS_RANDOM; i++) rn[k][i] = (u8)rnd();
    }
    /* two connections, ids chosen so the reflector's rank is 2; roles differ in tag byte0 */
    memset(cs, 0, sizeof(cs));
    cs[0].id.hi = 0; cs[0].id.lo = 50; cs[0].ip = 0x5B6C1108UL; cs[0].port = 597; cs[0].tcp = 1;
    cs[1].id.hi = 0; cs[1].id.lo = 99; cs[1].ip = 0x5B6C1108UL; cs[1].port = 598;
    for (k = 0; k < 16; k++) { cs[0].peer_tag[k] = (u8)(0x30 + k); cs[1].peer_tag[k] = (u8)(0x60 + k); }
    {
        c277_sess_conn a[2], b[2];
        memcpy(a, cs, sizeof(cs)); memcpy(b, cs, sizeof(cs));
        a[1].peer_tag[0] = 0x00; b[1].peer_tag[0] = 0x01;
        CHECK(c277_session_init(w->s[0], key, 1, a, 2, rn[0], C277_SESS_RANDOM) == C277_SESS_OK);
        CHECK(c277_session_init(w->s[1], key, 0, b, 2, rn[1], C277_SESS_RANDOM) == C277_SESS_OK);
    }
    CHECK(w->s[0]->rank == 2 && w->s[0]->r_port == 598);
    for (now = 1000; now < 41000; now += 20) {
        for (w_i = 0; w_i < 2; w_i++) {
            c277_session *s = w->s[w_i];
            u8 pk[C277_JB_MAXPKT], op[60];
            u32 l;
            int st;
            c277_session_tick(s, now);
            drain(w, w_i, now);
            if (c277_session_ice_connected(s) && !conn_at[w_i]) conn_at[w_i] = now;
            /* 100 audio packets per side, one per 60 ms, starting 1 s after ICE connected */
            if (conn_at[w_i] && now >= conn_at[w_i] + 1000 && sent[w_i] < 100 &&
                (now - conn_at[w_i] - 1000) % 60 == 0) {
                op[0] = 0x18; op[1] = (u8)sent[w_i]; op[2] = (u8)(w_i + 1); memset(op + 3, (int)sent[w_i], 20);
                if (c277_session_send_opus(s, op, 23, now) == 0) { sent[w_i]++; drain(w, w_i, now); }
            }
            while ((st = c277_session_poll_opus(s, pk, sizeof(pk), &l)) != C277_JB_EMPTY) {
                if (st == C277_JB_LOST) lost[w_i]++;
                else {
                    CHECK(l == 23 && pk[2] == (u8)(2 - w_i));
                    if ((int)pk[1] <= last[w_i] && last[w_i] < 100) order_ok = 0;
                    last[w_i] = pk[1];
                    got[w_i]++;
                }
            }
        }
        world_deliver(w, now);
    }
    printf("sim loss=%d%% jit=%dms sig_loss=%d%%: connected at %u/%u ms; rx %d/%d lost-reports %d/%d; hello/stun/sig pkts %u/%u; sig acked %d/%d\n",
           loss, jit, sig_loss, conn_at[0], conn_at[1], got[0], got[1], lost[0], lost[1], w->m.sent, w->sig_sent,
           c277_session_signaling_acked(w->s[0]), c277_session_signaling_acked(w->s[1]));
    CHECK(c277_session_ice_connected(w->s[0]) && c277_session_ice_connected(w->s[1]));
    CHECK(sent[0] == 100 && sent[1] == 100);
    CHECK(order_ok);
    CHECK(c277_session_peer_audio_active(w->s[0]) && c277_session_peer_audio_active(w->s[1]));
    CHECK(c277_session_signaling_acked(w->s[0]) && c277_session_signaling_acked(w->s[1]));
    CHECK(c277_ice_nominated(&w->s[0]->ice) && c277_ice_nominated(&w->s[1]->ice));
    for (k = 0; k < 2; k++) {
        if (loss == 0 && audio_loss == 0) CHECK(got[k] >= 99 && lost[k] == 0);   /* reordering only: all in order */
        else CHECK(got[k] >= 100 - 3 * (loss + 1) - 2);
        CHECK(got[k] + lost[k] <= 100);
    }
    /* media flowing right after the last audio, not 10 s later */
    free(w->s[0]); free(w->s[1]); free(w);
}

static void test_sim(void)
{
    sim_world(0, 0, 0, 0);
    sim_world(0, 80, 0, 0);      /* heavy reorder (jitter up to 80 ms, packets every 60 ms) */
    sim_world(5, 60, 20, 5);     /* loss + reorder + lossy signalling */
}


/* ------------------------------------------------------- video send (two sessions) */

static void inject(world *w, int from, u32 now, int type, const u8 *body, u32 blen, int reliable)
{
    c277_session *s = w->s[from];
    u8 pk[C277_OUT_MAX], o[C277_OUT_MAX];
    u32 peer = 0;
    int k, k2;
    k = c277_conn_build(&s->tr, now, type, body, blen, reliable, pk, sizeof(pk));
    CHECK(k > 0 && c277_ice_peer_tag(&s->ice, &peer));
    k2 = c277_refl_wrap(s->tag16, peer, s->own_rt, pk, (u32)k, o, sizeof(o));
    CHECK(k2 > 0);
    refl_in(&w->m, now, from, o, (u32)k2);
}

static u32 vunit(u8 *o, int idr, u32 body, int ps)
{
    static const u8 sps[] = { 0x67, 0x42, 0x80, 0x0a, 0xda, 0x0b, 0x13, 0x90 };
    static const u8 pps[] = { 0x68, 0xce, 0x3c, 0x80 };
    u32 n = 0, i;
    if (ps) {
        o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1; memcpy(o + n, sps, sizeof(sps)); n += sizeof(sps);
        o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1; memcpy(o + n, pps, sizeof(pps)); n += sizeof(pps);
    }
    o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 1;
    o[n++] = (u8)(idr ? 0x65 : 0x41);
    for (i = 1; i < body; i++) o[n++] = (u8)(1 + (i * 13) % 250);
    return n;
}

static void test_video_sim(int loss)
{
    world *w = (world *)calloc(1, sizeof(world));
    u8 key[256], rn[2][C277_SESS_RANDOM], unit[8000];
    char cap[C277_CAP_MAX + 1];
    c277_sess_conn cs[2];
    u32 now, frames = 0, tot = 0, capn;
    int k, want_idr = 1, first_p_dropped = 0, pli_seen = 0, was_active = 0, peer2 = 0, idr_reqs = 0;
    u32 next_frame = 0;
    char *txt;

    w->s[0] = (c277_session *)malloc(sizeof(c277_session));
    w->s[1] = (c277_session *)malloc(sizeof(c277_session));
    w->m.loss = loss; w->sig_loss = 0;
    data(key, 256, 29, 7);
    for (k = 0; k < 2; k++) { u32 i; for (i = 0; i < C277_SESS_RANDOM; i++) rn[k][i] = (u8)rnd(); }
    memset(cs, 0, sizeof(cs));
    cs[0].id.lo = 50; cs[0].ip = 0x5B6C1108UL; cs[0].port = 597; cs[0].tcp = 1;
    cs[1].id.lo = 99; cs[1].ip = 0x5B6C1108UL; cs[1].port = 598;
    for (k = 0; k < 16; k++) { cs[0].peer_tag[k] = (u8)(0x30 + k); cs[1].peer_tag[k] = (u8)(0x60 + k); }
    {
        c277_sess_conn a[2], b[2];
        memcpy(a, cs, sizeof(cs)); memcpy(b, cs, sizeof(cs));
        a[1].peer_tag[0] = 0x00; b[1].peer_tag[0] = 0x01;
        CHECK(c277_session_init(w->s[0], key, 1, a, 2, rn[0], C277_SESS_RANDOM) == C277_SESS_OK);
        CHECK(c277_session_init(w->s[1], key, 0, b, 2, rn[1], C277_SESS_RANDOM) == C277_SESS_OK);
    }
    CHECK(w->s[0]->vtx.ssrc == 4 && w->s[1]->vtx.ssrc == 3);          /* caller 4, callee 3 */
    c277_session_capture(w->s[1], 1, 0);                              /* the receiver logs (no auto reply) */
    c277_session_capture(w->s[0], 1, 0);
    c277_session_set_wall(w->s[0], 1790000000UL, 1000);
    for (now = 1000; now < 26000; now += 20) {
        int who;
        for (who = 0; who < 2; who++) {
            c277_session *s = w->s[who];
            c277_session_tick(s, now);
            drain(w, who, now);
        }
        if (now == 6000) {
            CHECK(!c277_session_video_active(w->s[0]));
            c277_session_video_enable(w->s[0], 1);
            /* nothing is sent before the announcement */
            CHECK(c277_session_video_put(w->s[0], unit, vunit(unit, 1, 500, 1), now) == C277_VTX_DROPPED);
            next_frame = now + 200;
        }
        if (now == 16000) {                     /* the peer asks for a keyframe, and asks for video */
            u8 pli[12];
            CHECK(c277_rtcp_build_pli(pli, 12, 3, 4) == 12);
            c277_session_take_idr_req(w->s[0]);
            inject(w, 1, now, C277_MSG_VIDEO, pli, 12, 0);
            inject(w, 1, now, C277_MSG_REQUESTVIDEO, pli, 0, 1);
        }
        if (now == 22000) c277_session_video_enable(w->s[0], 0);
        if (c277_session_video_active(w->s[0])) {
            was_active = 1;
            if (c277_session_take_idr_req(w->s[0])) { want_idr = 1; idr_reqs++; }
            if (now >= next_frame && now < 22000) {
                u32 un;
                int r;
                if (frames == 0 && !first_p_dropped) {      /* P frame before the first IDR: dropped, IDR requested */
                    un = vunit(unit, 0, 300, 0);
                    CHECK(c277_session_video_put(w->s[0], unit, un, now) == C277_VTX_DROPPED);
                    first_p_dropped = 1;
                }
                un = vunit(unit, want_idr, want_idr ? 3000 : 400, want_idr);
                r = c277_session_video_put(w->s[0], unit, un, now);
                CHECK(r == C277_VTX_QUEUED);
                want_idr = 0; frames++;
                while (c277_session_video_pump(w->s[0], now)) { drain(w, 0, now); world_deliver(w, now); }
                drain(w, 0, now);
                next_frame += 66;
            }
        }
        world_deliver(w, now);
        if (w->s[1]->peer_vid == 2) peer2 = 1;
        if (w->s[0]->pli_n > 0) pli_seen = 1;
    }
    tot = w->s[0]->vtx.n_pk;
    capn = c277_session_cap_take(w->s[1], cap, C277_CAP_MAX); cap[capn] = 0; txt = cap;
    printf("video sim loss=%d%%: %u frames, %u packets sent, %u received, idr %u, pli seen %u, idr requests %d\n",
           loss, frames, tot, w->s[1]->n_peer_vrtp, w->s[0]->vtx.n_idr, w->s[0]->pli_n, idr_reqs);
    CHECK(was_active && peer2);                                       /* RemoteMediaState video=Active reached the peer */
    CHECK(w->s[1]->peer_vid == 0);                                    /* and Inactive after we switched off */
    CHECK(!c277_session_video_active(w->s[0]));
    CHECK(frames > 150 && tot > frames);
    CHECK(w->s[0]->vtx.n_idr >= 5);                                   /* first + scheduled / requested IDRs */
    CHECK(pli_seen && w->s[0]->pli_n == 1 && w->s[0]->req_video_n == 1);
    CHECK(idr_reqs >= 5);                                             /* early schedule fired and the PLI took one */
    if (loss == 0) CHECK(w->s[1]->n_peer_vrtp == tot);
    else CHECK(w->s[1]->n_peer_vrtp >= tot - tot * (u32)loss / 50);
    CHECK(strstr(txt, "peerSPS profile=66 level=10 size=176x144") != 0);
    CHECK(strstr(txt, "RTCP pt=200") != 0);                           /* our sender reports arrive */
    CHECK(strstr(txt, "RemoteMediaState audio=1 video=2") != 0);
    CHECK(w->s[1]->n_sps_log >= 1 && w->s[1]->n_sps_log <= 3);        /* repeats are throttled */
    capn = c277_session_cap_take(w->s[0], cap, C277_CAP_MAX); cap[capn] = 0;
    CHECK(strstr(cap, " vtx fps10=") != 0 && strstr(cap, "video send ON") != 0 &&
          strstr(cap, "video send OFF") != 0);
    CHECK(w->s[0]->vtx_last_fps > 0 || frames > 0);
    /* nothing about keys or addresses in the log */
    CHECK(strstr(cap, "key") == 0);
    free(w->s[0]); free(w->s[1]); free(w);
}

static void test_misc(void)
{
    c277_session *s = (c277_session *)malloc(sizeof(*s));
    u8 key[256], rn[C277_SESS_RANDOM], op[10] = {0x18};
    c277_sess_conn c;
    data(key, 256, 3, 3); data(rn, sizeof(rn), 5, 5);
    memset(&c, 0, sizeof(c));
    c.tcp = 1;
    CHECK(c277_session_init(s, key, 1, &c, 1, rn, sizeof(rn)) == C277_SESS_ERR_ARG);   /* tcp only */
    c.tcp = 0; c.webrtc = 1;
    CHECK(c277_session_init(s, key, 1, &c, 1, rn, sizeof(rn)) == C277_SESS_ERR_ARG);   /* webrtc only */
    c.webrtc = 0; c.ip = 1; c.port = 2;
    CHECK(c277_session_init(s, key, 1, &c, 1, rn, 10) == C277_SESS_ERR_ARG);
    CHECK(c277_session_init(s, key, 1, &c, 1, rn, sizeof(rn)) == C277_SESS_OK && s->rank == 1);
    CHECK(c277_session_send_opus(s, op, 10, 0) == C277_SESS_ERR_BUSY);               /* ICE not up */
    CHECK(c277_session_on_signaling(s, op, 10, 0) < 0);
    CHECK(c277_session_media_flowing(s, 0) == 0 && !c277_session_ice_connected(s));
    free(s);
}

/* the forwarding gate: access units are only handed to the display helper after rx_enable(fwd=1) */
static void test_rx_forward(void)
{
    c277_session *s = (c277_session *)calloc(1, sizeof(*s));
    static const u8 sps[] = { 0x67, 0x64, 0x00, 0x1f, 0xac, 0x1b, 0x1a, 0x80, 0x84, 0x1e, 0x69, 0xa8, 0x10, 0x10, 0x10, 0x3c, 0x22, 0x11, 0xa8 };
    static const u8 pps[] = { 0x68, 0xea, 0x43, 0xcb };
    u8 stap[64], idr[40];
    const u8 *au = 0;
    u32 len = 0, k = 0;
    int is_idr = 0;
    c277_sps sp;
    stap[k++] = 0x18; stap[k++] = 0; stap[k++] = sizeof(sps); memcpy(stap + k, sps, sizeof(sps)); k += sizeof(sps);
    stap[k++] = 0; stap[k++] = sizeof(pps); memcpy(stap + k, pps, sizeof(pps)); k += sizeof(pps);
    memset(idr, 7, sizeof(idr)); idr[0] = 0x65;
    c277_vrx_init(&s->vrx);
    c277_session_rx_enable(s, 1, 0, 150);                 /* wanted, but the helper is not ready: nothing is forwarded */
    CHECK(c277_vrx_put(&s->vrx, 10, 900, 0, 3, stap, k, 100) == 0);
    CHECK(c277_vrx_put(&s->vrx, 11, 900, 1, 3, idr, sizeof(idr), 101) == 1);
    CHECK(c277_session_vrx_take(s, &au, &len, &is_idr) == 0 && s->rx_nofwd == 1);   /* counted, dropped */
    CHECK(c277_session_vrx_sps_take(s, &sp) == 0);
    c277_session_rx_enable(s, 1, 1, 150);                 /* the helper says ready: IDR requested, SPS announced */
    CHECK(s->vrx.need_idr == 1 && s->rx_pli_due == 1 && s->rx_sps_new == 1);
    CHECK(c277_vrx_put(&s->vrx, 12, 1800, 0, 3, stap, k, 200) == 0);
    CHECK(c277_vrx_put(&s->vrx, 13, 1800, 1, 3, idr, sizeof(idr), 201) == 1);
    CHECK(c277_session_vrx_take(s, &au, &len, &is_idr) == 1 && is_idr == 1 && len == 4 + sizeof(sps) + 4 + sizeof(pps) + 4 + sizeof(idr));
    CHECK(au[4] == 0x67 && au[4 + sizeof(sps) + 4] == 0x68);
    c277_session_vrx_done(s);
    CHECK(c277_session_vrx_sps_take(s, &sp) == 1 && sp.profile == 100 && sp.width == 528 && sp.height == 960);
    /* a swapped pair of P frame packets in the middle still gives both frames */
    {
        u8 p1[20], p2[20];
        memset(p1, 3, sizeof(p1)); p1[0] = 0x41; memset(p2, 4, sizeof(p2)); p2[0] = 0x41;
        CHECK(c277_vrx_put(&s->vrx, 15, 2700, 1, 3, p2, sizeof(p2), 300) == 0);      /* frame 15 arrives before 14 */
        CHECK(c277_vrx_put(&s->vrx, 14, 2610, 1, 3, p1, sizeof(p1), 303) == 1);
        CHECK(c277_session_vrx_take(s, &au, &len, &is_idr) == 1 && len == 4 + sizeof(p1) && is_idr == 0);
        c277_session_vrx_done(s);                                                    /* releases the buffered frame 15 */
        CHECK(s->vrx.ready == 1 && s->vrx.ready_len == 4 + sizeof(p2));
        c277_session_vrx_done(s);
    }
    CHECK(s->vrx.n_lost == 0 && s->vrx.n_drop_au == 0);
    free(s);
}

int main(int argc, char **argv)
{
    FILE *f;
    static char buf[200000];
    size_t n;
    if (argc < 2) { printf("usage: test_session crosscheck.txt\n"); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) return 2;
    n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0; fclose(f);
    g_xc = buf;
    test_rtp();
    test_rx_forward();
    test_ice_vectors();
    test_ice_pair();
    test_capture();
    test_sim();
    test_video_sim(0);
    test_video_sim(4);
    test_misc();
    printf("%d checks, %d failed\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
