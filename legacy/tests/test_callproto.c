/* Host tests for callproto. Build: see run_tests.sh. usage: test_callproto crosscheck.txt */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "callproto.h"

static int g_fail = 0, g_n = 0;
#define CHECK(cond) do { g_n++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static u8 KEY[256], KEY2[256], TAG[16];

static void setup(void)
{
    int i;
    for (i = 0; i < 256; i++) { KEY[i] = (u8)((i * 7 + 3) & 255); KEY2[i] = KEY[i]; }
    KEY2[100] ^= 1;
    for (i = 0; i < 16; i++) TAG[i] = (u8)(0xA0 + i);
}

static void pad_fixed(void *user, u8 *buf, u32 n)
{
    u32 i; (void)user;
    for (i = 0; i < n; i++) buf[i] = (u8)(0xC0 + i);
}

static u32 rng_state = 12345;
static u32 rnd(void) { rng_state = rng_state * 1664525UL + 1013904223UL; return rng_state >> 8; }

static int hex2bin(const char *h, u8 *out, int cap)
{
    int n = 0;
    while (h[0] && h[1] && h[0] != '\n' && n < cap) {
        unsigned v; sscanf(h, "%2x", &v); out[n++] = (u8)v; h += 2;
    }
    return n;
}

/* ---------------------------------------------------------------- (a) */
static void test_layouts(void)
{
    static const u8 init_exp[19] = {9,0,0,0, 3,0,0,0, 0,0,0,0, 1, 0x53,0x55,0x50,0x4F, 0, 0};
    static const u8 ack_exp[18] = {9,0,0,0, 3,0,0,0, 1, 1, 1, 0x53,0x55,0x50,0x4F, 60,0, 1};
    static const u8 rp_exp[40] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFE,0xFF,0xFF,0xFF,
        1,2,3,4,5,6,7,8};
    u8 b[64], opus[40], id8[8] = {1,2,3,4,5,6,7,8};
    tgcp_init_ack_info ia;
    const u8 *op; u8 sid; u32 pts, ol; int i, n;
    u32 pr, mr;

    CHECK(tgcp_make_init(b, 64) == 19 && memcmp(b, init_exp, 19) == 0);
    CHECK(tgcp_parse_init(b, 19, &pr, &mr) == 0 && pr == 9 && mr == 3);
    CHECK(tgcp_make_init_ack(b, 64) == 18 && memcmp(b, ack_exp, 18) == 0);
    CHECK(tgcp_parse_init_ack(b, 18, &ia) == 0 && ia.proto == 9 && ia.min_proto == 3 &&
          ia.n_streams == 1 && ia.audio_stream_id == 1 && ia.audio_codec == 0x4F505553UL && ia.frame_ms == 60);
    CHECK(tgcp_make_init(b, 18) < 0);
    for (i = 0; i < 40; i++) opus[i] = (u8)i;
    n = tgcp_make_stream_data(opus, 40, 120, b, 64);
    CHECK(n == 46 && b[0] == 0x01 && b[1] == 0x28 && b[2] == 120 && b[3] == 0 && b[4] == 0 && b[5] == 0 &&
          memcmp(b + 6, opus, 40) == 0);
    CHECK(tgcp_parse_stream_data(b, (u32)n, &sid, &pts, &op, &ol) == 46 && sid == 1 && pts == 120 && ol == 40 && op == b + 6);
    {   /* LEN16 form, 300 bytes, pts 0x01020304 */
        u8 big[320], big2[320];
        memset(big, 0x5a, 300);
        n = tgcp_make_stream_data(big, 300, 0x01020304UL, big2, 320);
        CHECK(n == 307 && big2[0] == 0x41 && big2[1] == 0x2C && big2[2] == 0x01 && big2[3] == 4 && big2[4] == 3 &&
              big2[5] == 2 && big2[6] == 1);
        CHECK(tgcp_parse_stream_data(big2, (u32)n, &sid, &pts, &op, &ol) == 307 && ol == 300 && pts == 0x01020304UL);
    }
    {   /* EXTRA_FEC trailer is skipped: len16 = 3|0x2000, one fec frame of 2 bytes */
        static const u8 f[] = {0x41, 0x03, 0x20, 0x3C,0,0,0, 7,8,9, 1, 2, 0xAA,0xBB};
        CHECK(tgcp_parse_stream_data(f, sizeof(f), &sid, &pts, &op, &ol) == (int)sizeof(f) && ol == 3 && pts == 60);
    }
    CHECK(tgcp_parse_stream_data(b, 20, &sid, &pts, &op, &ol) < 0);     /* truncated */
    CHECK(tgcp_make_ping(b, 64) == 0 && tgcp_make_nop(b, 64) == 0);
    CHECK(tgcp_make_pong(0x11223344UL, b, 64) == 4 && b[0] == 0x44 && b[3] == 0x11);
    CHECK(tgcp_make_reflector_ping(TAG, id8, b, 64) == 40 && memcmp(b, rp_exp, 40) == 0);
    CHECK(tgcp_is_reflector_reply(b, 40, NULL) == 2);
    {   /* SELF_INFO reply */
        u8 r[68];
        memset(r, 0, sizeof(r)); memcpy(r, TAG, 16); memset(r + 16, 0xFF, 12);
        r[28] = 0xC7; r[29] = 0x72; r[30] = 0x15; r[31] = 0xC0;
        for (i = 0; i < 8; i++) r[36 + i] = (u8)(0x10 + i);
        CHECK(tgcp_is_reflector_reply(r, 68, id8) == 1 && id8[0] == 0x10 && id8[7] == 0x17);
        CHECK(tgcp_is_reflector_reply(r, 20, NULL) == 0);
    }
    {   /* header layout: inspect the decrypted packet kept in scratch */
        tgcp_ctx a, c; u8 dg[256], t, pl[64]; u32 pn = 64; int dn;
        tgcp_init(&a, KEY, 1, TAG); tgcp_init(&c, KEY, 0, TAG);
        a.have_rx = 1; a.last_remote_seq = 1000; a.rw[0] = 0xB; a.out_seq = 77;
        dn = tgcp_build_datagram(&a, TGCP_PKT_PING, NULL, 0, dg, sizeof(dg));
        CHECK(dn == 16 + 16 + 32);                       /* 2+14 -> 16 pad */
        CHECK(tgcp_parse_datagram(&c, dg, (u32)dn, &t, pl, &pn) == 0 && t == 6 && pn == 0);
        CHECK(c.scratch[0] == 14 && c.scratch[1] == 0);          /* u16 len */
        CHECK(c.scratch[2] == 6);                                /* type */
        CHECK(c.scratch[3] == 0xE8 && c.scratch[4] == 0x03 && c.scratch[5] == 0 && c.scratch[6] == 0); /* ack_seq 1000 */
        CHECK(c.scratch[7] == 77 && c.scratch[8] == 0);          /* seq */
        CHECK(c.scratch[9] == 0 && c.scratch[10] == 0);          /* seq hi */
        CHECK(c.scratch[11] == 0 && c.scratch[12] == 0 && c.scratch[13] == 0 && c.scratch[14] == 0xA0); /* mask */
        CHECK(c.scratch[15] == 0);                               /* flags */
    }
    /* padding rule: inner 2+14+len; len=0 -> 16 pad; len=14 -> 30 -> pad 2+16=18 */
    {
        tgcp_ctx a; u8 dg[256], pl[14]; memset(pl, 1, 14);
        tgcp_init(&a, KEY, 1, TAG);
        CHECK(tgcp_build_datagram(&a, 4, pl, 14, dg, 256) == 32 + 48);   /* 30 + 18 */
        CHECK(tgcp_build_datagram(&a, 4, pl, 0, dg, 256) == 32 + 32);    /* 16 + 16 */
        CHECK(tgcp_build_datagram(&a, 4, pl, 1, dg, 256) == 32 + 48);    /* 17 + 31 */
        CHECK(tgcp_build_datagram(&a, 4, pl, 14, dg, 40) == TGCP_E_CAP);
    }
}

/* ---------------------------------------------------------------- (b) */
static void test_roundtrip(void)
{
    tgcp_ctx caller, callee, wrong;
    u8 dg[512], pl[600], t, in_pl[100];
    u32 pn, i, k;
    int n;

    tgcp_init(&caller, KEY, 1, TAG);
    tgcp_init(&callee, KEY, 0, TAG);
    tgcp_init(&wrong, KEY2, 0, TAG);
    for (i = 0; i < 100; i++) in_pl[i] = (u8)(i * 3);

    n = tgcp_build_datagram(&caller, TGCP_PKT_STREAM_DATA, in_pl, 100, dg, sizeof(dg));
    CHECK(n > 0 && ((n - 32) % 16) == 0);
    pn = sizeof(pl);
    CHECK(tgcp_parse_datagram(&callee, dg, (u32)n, &t, pl, &pn) == TGCP_OK);
    CHECK(t == TGCP_PKT_STREAM_DATA && pn == 100 && memcmp(pl, in_pl, 100) == 0);
    CHECK(tgcp_last_rx_seq(&callee) == 1);
    /* duplicate */
    pn = sizeof(pl);
    CHECK(tgcp_parse_datagram(&callee, dg, (u32)n, &t, pl, &pn) == TGCP_DUP);
    /* a caller must not accept its own datagram (wrong direction x) */
    pn = sizeof(pl);
    CHECK(tgcp_parse_datagram(&caller, dg, (u32)n, &t, pl, &pn) == TGCP_E_MSGKEY);
    /* wrong key */
    pn = sizeof(pl);
    CHECK(tgcp_parse_datagram(&wrong, dg, (u32)n, &t, pl, &pn) == TGCP_E_MSGKEY);
    /* wrong tag */
    {   u8 bad[512]; memcpy(bad, dg, (size_t)n); bad[3] ^= 0x10; pn = sizeof(pl);
        CHECK(tgcp_parse_datagram(&callee, bad, (u32)n, &t, pl, &pn) == TGCP_E_TAG); }
    /* every single flipped bit after the tag is rejected, and state is untouched */
    {
        tgcp_ctx fresh; int bad_ok = 0; u32 bit;
        tgcp_init(&fresh, KEY, 0, TAG);
        for (bit = 16 * 8; bit < (u32)n * 8; bit++) {
            u8 m[512]; memcpy(m, dg, (size_t)n); m[bit >> 3] ^= (u8)(1 << (bit & 7));
            pn = sizeof(pl);
            if (tgcp_parse_datagram(&fresh, m, (u32)n, &t, pl, &pn) >= 0) bad_ok++;
        }
        CHECK(bad_ok == 0);
        CHECK(fresh.have_rx == 0);
        pn = sizeof(pl);
        CHECK(tgcp_parse_datagram(&fresh, dg, (u32)n, &t, pl, &pn) == TGCP_OK);
    }
    /* too short / bad length / small output cap */
    pn = sizeof(pl); CHECK(tgcp_parse_datagram(&callee, dg, 20, &t, pl, &pn) == TGCP_E_SHORT);
    pn = sizeof(pl); CHECK(tgcp_parse_datagram(&callee, dg, (u32)n - 1, &t, pl, &pn) == TGCP_E_ALIGN);
    {
        tgcp_ctx f; tgcp_init(&f, KEY, 0, TAG); pn = 10;
        CHECK(tgcp_parse_datagram(&f, dg, (u32)n, &t, pl, &pn) == TGCP_E_CAP);
        CHECK(f.have_rx == 0);
    }
    /* reverse direction */
    n = tgcp_build_datagram(&callee, TGCP_PKT_NOP, NULL, 0, dg, sizeof(dg));
    pn = sizeof(pl);
    CHECK(tgcp_parse_datagram(&caller, dg, (u32)n, &t, pl, &pn) == TGCP_OK && t == TGCP_PKT_NOP && pn == 0);
    /* callee packet carries ack for caller's seq 1 -> caller's unacked cleared */
    CHECK(tgcp_unacked_out(&caller) == 0);
    CHECK(tgcp_unacked_out(&callee) == 1);

    /* reorder + window: seqs 1..300 sent, delivered in odd orders, each accepted once */
    {
        tgcp_ctx a, b; u8 *store = (u8 *)malloc(300 * 80); int ln[300], ok = 0, dup = 0;
        u32 order[300], j, tmp;
        tgcp_init(&a, KEY, 1, TAG); tgcp_init(&b, KEY, 0, TAG);
        for (i = 0; i < 300; i++) {
            ln[i] = tgcp_build_datagram(&a, TGCP_PKT_NOP, NULL, 0, store + i * 80, 80);
            order[i] = i;
        }
        for (i = 0; i < 300; i += 10)    /* local shuffles within blocks of 10 */
            for (k = 9; k > 0; k--) { j = i + rnd() % (k + 1); tmp = order[i + k]; order[i + k] = order[j]; order[j] = tmp; }
        for (i = 0; i < 300; i++) {
            int r;
            pn = sizeof(pl);
            r = tgcp_parse_datagram(&b, store + order[i] * 80, (u32)ln[order[i]], &t, pl, &pn);
            if (r == TGCP_OK) ok++; else if (r == TGCP_DUP) dup++;
        }
        CHECK(ok == 300 && dup == 0);
        CHECK(b.last_remote_seq == 300);
        for (i = 0; i < 300; i += 7) {   /* replay everything: all dup / too old */
            pn = sizeof(pl);
            CHECK(tgcp_parse_datagram(&b, store + i * 80, (u32)ln[i], &t, pl, &pn) == TGCP_DUP);
        }
        free(store);
    }
}

/* ---------------------------------------------------------------- (d) */
static void test_crosscheck(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[8192];
    int got = 0;
    if (!f) { printf("FAIL cannot open %s\n", path); g_fail++; return; }
    while (fgets(line, sizeof(line), f)) {
        u8 exp[2048], out[2048], init_pl[19], sd[46], i_;
        int en = hex2bin(line + 2, exp, sizeof(exp)), n = -1;
        tgcp_ctx c;
        tgcp_init(&c, KEY, line[0] != 'B', TAG);
        tgcp_set_pad_source(&c, pad_fixed, NULL);
        if (line[0] == 'A') {
            c.out_seq = 1;
            tgcp_make_init(init_pl, 19);
            n = tgcp_build_datagram(&c, TGCP_PKT_INIT, init_pl, 19, out, sizeof(out));
        } else if (line[0] == 'B') {
            c.out_seq = 77; c.have_rx = 1; c.last_remote_seq = 1000; c.rw[0] = 0xB;
            sd[0] = 0x01; sd[1] = 40; sd[2] = 120; sd[3] = sd[4] = sd[5] = 0;
            for (i_ = 0; i_ < 40; i_++) sd[6 + i_] = i_;
            n = tgcp_build_datagram(&c, TGCP_PKT_STREAM_DATA, sd, 46, out, sizeof(out));
        } else if (line[0] == 'C') {
            c.out_seq = 5; c.have_rx = 1; c.last_remote_seq = 3; c.rw[0] = 0x80000001UL; c.rw[1] = 1;
            n = tgcp_build_datagram(&c, TGCP_PKT_PING, NULL, 0, out, sizeof(out));
        } else continue;
        got++;
        CHECK(n == en && n > 0 && memcmp(out, exp, (size_t)en) == 0);
        if (n != en || memcmp(out, exp, (size_t)en)) printf("  vector %c mismatch (C %d bytes, py %d)\n", line[0], n, en);
    }
    fclose(f);
    CHECK(got == 3);
}

/* ---------------------------------------------------------------- (c) */
#define RQ 512
typedef struct { int used, to; u32 at; int len; u8 d[1200]; } relay_pkt;
static relay_pkt relay[RQ];
static int loss_pct, max_delay;

static void relay_send(int to, const u8 *d, int len, u32 now)
{
    int i;
    if ((int)(rnd() % 100) < loss_pct) return;
    for (i = 0; i < RQ; i++) if (!relay[i].used) {
        relay[i].used = 1; relay[i].to = to; relay[i].len = len;
        relay[i].at = now + (max_delay ? rnd() % (u32)(max_delay + 1) : 0);
        memcpy(relay[i].d, d, (size_t)len);
        return;
    }
    CHECK(0 && "relay overflow");
}

typedef struct { int sent, got, bad, dups; u32 expect_next_min; } audio_stat;

static void frame_for(u32 pts, u8 *f) { int i; for (i = 0; i < 40; i++) f[i] = (u8)(pts / 60 + (u32)i * 5); }

static void deliver(tgcp_ctx *c, int who, audio_stat *st, const u8 *d, int len, int *nop_seen)
{
    u8 t, pl[1200]; u32 pn = sizeof(pl); int r;
    r = tgcp_parse_datagram(c, d, (u32)len, &t, pl, &pn);
    if (r != TGCP_OK) { if (r != TGCP_DUP) st->bad++; else st->dups++; return; }
    if (t == TGCP_PKT_NOP) nop_seen[who]++;
    if (t == TGCP_PKT_STREAM_DATA) {
        const u8 *op; u32 ol, pts; u8 sid, exp[40];
        if (tgcp_parse_stream_data(pl, pn, &sid, &pts, &op, &ol) < 0) { st->bad++; return; }
        frame_for(pts, exp);
        if (sid != 1 || ol != 40 || (pts % 60) != 0 || memcmp(op, exp, 40) != 0) st->bad++;
        else st->got++;
    }
}

static void run_sim(int loss, int delay, int *connected_ok, audio_stat *sa, audio_stat *sb, int *nops)
{
    tgcp_ctx a, b, *cx[2];
    audio_stat *st[2];
    u32 now, next_audio[2];
    int i, w, n, idle;
    u8 dg[1200], fr[40];

    memset(relay, 0, sizeof(relay));
    memset(sa, 0, sizeof(*sa)); memset(sb, 0, sizeof(*sb));
    nops[0] = nops[1] = 0;
    loss_pct = loss; max_delay = delay;
    tgcp_init(&a, KEY, 1, TAG); tgcp_init(&b, KEY, 0, TAG);
    cx[0] = &a; cx[1] = &b; st[0] = sa; st[1] = sb;
    next_audio[0] = next_audio[1] = 0;

    idle = 0;
    for (now = 0; now < 120000; now += 10) {
        /* deliver due packets (oldest first) */
        for (;;) {
            int best = -1;
            for (i = 0; i < RQ; i++)
                if (relay[i].used && relay[i].at <= now && (best < 0 || relay[i].at < relay[best].at)) best = i;
            if (best < 0) break;
            relay[best].used = 0;
            deliver(cx[relay[best].to], relay[best].to, st[relay[best].to], relay[best].d, relay[best].len, nops);
        }
        for (w = 0; w < 2; w++) {
            while ((n = tgcp_tick(cx[w], now, dg, sizeof(dg))) > 0) relay_send(1 - w, dg, n, now);
            CHECK(n == 0);
            if (tgcp_get_state(cx[w]) == TGCP_ST_CONNECTED) {
                if (next_audio[w] == 0) next_audio[w] = now;
                while (now >= next_audio[w] && st[w]->sent < 200) {
                    u32 pts = (u32)st[w]->sent * 60;
                    frame_for(pts, fr);
                    CHECK(cx[w]->pts_out == pts);
                    n = tgcp_send_audio(cx[w], fr, 40, dg, sizeof(dg));
                    CHECK(n > 0);
                    relay_send(1 - w, dg, n, now);
                    st[w]->sent++; next_audio[w] += 60;
                }
            }
        }
        if (sa->sent == 200 && sb->sent == 200) {
            int pending = 0;
            for (i = 0; i < RQ; i++) pending += relay[i].used;
            if (!pending && ++idle > 5) break;
        }
    }
    *connected_ok = tgcp_get_state(&a) == TGCP_ST_CONNECTED && tgcp_get_state(&b) == TGCP_ST_CONNECTED;

    /* lossless drain: NOPs both ways carry acks and push every old seq out of the mask */
    loss_pct = 0; max_delay = 0;
    for (i = 0; i < 40; i++) {
        for (w = 0; w < 2; w++) {
            n = tgcp_build_datagram(cx[w], TGCP_PKT_NOP, NULL, 0, dg, sizeof(dg));
            relay_send(1 - w, dg, n, now);
        }
        for (w = 0; w < 2; w++) { /* deliver */
            int j;
            for (j = 0; j < RQ; j++) if (relay[j].used && relay[j].to == w) {
                relay[j].used = 0;
                deliver(cx[w], w, st[w], relay[j].d, relay[j].len, nops);
            }
        }
    }
    CHECK(tgcp_unacked_out(&a) <= 1 && tgcp_unacked_out(&b) <= 1);   /* only the very last NOP may be in flight */
    printf("  sim loss=%d%% delay=%dms: A sent=%d got=%d bad=%d | B sent=%d got=%d bad=%d | unacked A=%u B=%u lostA=%u lostB=%u\n",
           loss, delay, sa->sent, sa->got, sa->bad, sb->sent, sb->got, sb->bad,
           tgcp_unacked_out(&a), tgcp_unacked_out(&b), a.lost_out, b.lost_out);
}

static void test_sim(void)
{
    int ok, nops[2];
    audio_stat sa, sb;
    run_sim(0, 90, &ok, &sa, &sb, nops);          /* reordering only */
    CHECK(ok);
    CHECK(sa.got == 200 && sb.got == 200 && sa.bad == 0 && sb.bad == 0);
    rng_state = 777;
    run_sim(20, 90, &ok, &sa, &sb, nops);         /* 20% loss + reordering */
    CHECK(ok);
    CHECK(sa.bad == 0 && sb.bad == 0);
    CHECK(sa.sent == 200 && sb.sent == 200);
    CHECK(sa.got >= 140 && sa.got <= 200 && sb.got >= 140 && sb.got <= 200);   /* ~80% survive */
}

/* ---------------------------------------------------------------- timers */
static void test_timing(void)
{
    tgcp_ctx a, b; u8 dg[256], pl[64], t; u32 now, pn; int n, inits = 0, i;

    /* INIT every 500 ms, new seq each time, until INIT_ACK; FAILED after 30 s */
    tgcp_init(&a, KEY, 1, TAG);
    for (now = 0; now < 2000; now += 10) {
        n = tgcp_tick(&a, now, dg, sizeof(dg));
        if (n > 0) inits++;
    }
    CHECK(inits == 4 && a.out_seq == 5);            /* t=0,500,1000,1500 */
    CHECK(tgcp_get_state(&a) == TGCP_ST_INIT_SENT);
    for (; now < 31000; now += 10) tgcp_tick(&a, now, dg, sizeof(dg));
    CHECK(tgcp_get_state(&a) == TGCP_ST_FAILED);

    /* connected: 2 s reconnecting flag, 20 s failure, ping every 10 s, pong reply */
    tgcp_init(&a, KEY, 1, TAG); tgcp_init(&b, KEY, 0, TAG);
    tgcp_tick(&a, 0, dg, sizeof(dg));
    n = tgcp_make_init_ack(pl, 64);
    n = tgcp_build_datagram(&b, TGCP_PKT_INIT_ACK, pl, (u32)n, dg, sizeof(dg));
    pn = 64; CHECK(tgcp_parse_datagram(&a, dg, (u32)n, &t, pl, &pn) == TGCP_OK);
    CHECK(tgcp_get_state(&a) == TGCP_ST_CONNECTED && tgcp_got_init_ack(&a) && !tgcp_got_init(&a));
    CHECK(!tgcp_is_reconnecting(&a));
    tgcp_tick(&a, 1000, dg, sizeof(dg)); CHECK(!tgcp_is_reconnecting(&a));
    tgcp_tick(&a, 2100, dg, sizeof(dg)); CHECK(tgcp_is_reconnecting(&a));
    {   int pings = 0;
        for (now = 2100; now < 19000; now += 10) {
            n = tgcp_tick(&a, now, dg, sizeof(dg));
            if (n > 0) { pn = 64; if (tgcp_parse_datagram(&b, dg, (u32)n, &t, pl, &pn) == 0 && t == TGCP_PKT_PING) pings++; }
        }
        CHECK(pings == 1);                           /* ~t=10 s */
        CHECK(tgcp_get_state(&a) == TGCP_ST_CONNECTED);
        for (; now < 21000; now += 10) tgcp_tick(&a, now, dg, sizeof(dg));
        CHECK(tgcp_get_state(&a) == TGCP_ST_FAILED);
    }
    /* B answers a PING with PONG carrying the ping seq; INIT is answered every time */
    tgcp_init(&a, KEY, 1, TAG); tgcp_init(&b, KEY, 0, TAG);
    n = tgcp_build_datagram(&a, TGCP_PKT_PING, NULL, 0, dg, sizeof(dg));
    pn = 64; CHECK(tgcp_parse_datagram(&b, dg, (u32)n, &t, pl, &pn) == 0);
    n = tgcp_tick(&b, 0, dg, sizeof(dg)); CHECK(n > 0);
    pn = 64; CHECK(tgcp_parse_datagram(&a, dg, (u32)n, &t, pl, &pn) == 0 && t == TGCP_PKT_PONG && pn == 4 && pl[0] == 1);
    for (i = 0; i < 3; i++) {   /* three INITs with distinct seqs -> three INIT_ACKs */
        int k = 0;
        pn = 64; tgcp_make_init(pl, 64);
        n = tgcp_build_datagram(&a, TGCP_PKT_INIT, pl, 19, dg, sizeof(dg));
        CHECK(tgcp_parse_datagram(&b, dg, (u32)n, &t, pl, &pn) == 0);
        while (tgcp_tick(&b, 10 + (u32)i, dg, sizeof(dg)) > 0) k++;
        CHECK(k >= 1);
    }
    /* NOP after > 10 received, un-acked packets */
    tgcp_init(&a, KEY, 1, TAG); tgcp_init(&b, KEY, 0, TAG);
    tgcp_tick(&b, 0, dg, sizeof(dg));   /* consumes the initial INIT */
    for (i = 0; i < 10; i++) {
        n = tgcp_build_datagram(&a, TGCP_PKT_NOP, NULL, 0, dg, sizeof(dg)); pn = 64;
        tgcp_parse_datagram(&b, dg, (u32)n, &t, pl, &pn);
    }
    CHECK(tgcp_tick(&b, 5, dg, sizeof(dg)) == 0);      /* exactly 10: not yet */
    n = tgcp_build_datagram(&a, TGCP_PKT_NOP, NULL, 0, dg, sizeof(dg)); pn = 64;
    tgcp_parse_datagram(&b, dg, (u32)n, &t, pl, &pn);
    n = tgcp_tick(&b, 6, dg, sizeof(dg)); CHECK(n > 0);
    pn = 64; CHECK(tgcp_parse_datagram(&a, dg, (u32)n, &t, pl, &pn) == 0 && t == TGCP_PKT_NOP);
    CHECK(tgcp_tick(&b, 7, dg, sizeof(dg)) == 0);
    CHECK(tgcp_unacked_out(&a) == 0);                  /* a's 11 NOPs all acked by that NOP */
}

int main(int argc, char **argv)
{
    setup();
    test_layouts();
    test_roundtrip();
    test_timing();
    test_sim();
    if (argc > 1) test_crosscheck(argv[1]);
    else { printf("FAIL no crosscheck file given\n"); g_fail++; }
    printf("%d checks, %d failures\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
