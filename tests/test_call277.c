/* Host tests for call277. usage: test_call277 crosscheck.txt */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c277_conn.h"
#include "c277_refl.h"
#include "c277_stun.h"
#include "rfc5769_vectors.h"

static int g_fail = 0, g_n = 0;
#define CHECK(cond) do { g_n++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static const char *g_xc;   /* crosscheck file contents */

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

static void unhex(const char *h, u8 *o)
{
    while (h[0] && h[1]) { unsigned v; sscanf(h, "%2x", &v); *o++ = (u8)v; h += 2; }
}

/* ------------------------------------------------------------ primitives */
static void test_prims(void)
{
    static const int lens[] = {0, 1, 55, 56, 63, 64, 65, 119, 120, 200};
    static const int kls[] = {0, 5, 64, 65, 100};
    u8 d[256], k[128], o[32], o2[200], key32[32], iv[16];
    char name[32];
    unsigned i;
    c277_sha1_ctx sc;
    c277_hmac_sha1_ctx hc;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        u32 crc;
        data(d, 256, 3, 1);
        c277_sha1(d, lens[i], o);
        sprintf(name, "sha1_%d", lens[i]); XC_EQ(name, o, 20);
        tgc_sha256(d, lens[i], o);
        sprintf(name, "sha256_%d", lens[i]); XC_EQ(name, o, 32);
        crc = c277_crc32_update(0, d, lens[i]);
        o[0] = (u8)(crc >> 24); o[1] = (u8)(crc >> 16); o[2] = (u8)(crc >> 8); o[3] = (u8)crc;
        sprintf(name, "crc_%d", lens[i]); XC_EQ(name, o, 4);
    }
    /* incremental split feeding */
    data(d, 200, 3, 1);
    c277_sha1_init(&sc);
    c277_sha1_update(&sc, d, 3); c277_sha1_update(&sc, d + 3, 70); c277_sha1_update(&sc, d + 73, 127);
    c277_sha1_final(&sc, o);
    XC_EQ("sha1_200", o, 20);
    CHECK(c277_crc32_update(c277_crc32_update(0, d, 77), d + 77, 123) == c277_crc32_update(0, d, 200));
    for (i = 0; i < sizeof(kls) / sizeof(kls[0]); i++) {
        data(k, kls[i], 7, 2); data(d, 77, 3, 1);
        c277_hmac_sha1_init(&hc, k, kls[i]);
        c277_hmac_sha1_update(&hc, d, 40); c277_hmac_sha1_update(&hc, d + 40, 37);
        c277_hmac_sha1_final(&hc, o);
        sprintf(name, "hmac_%d", kls[i]); XC_EQ(name, o, 20);
    }
    /* known answers */
    {
        u8 e[20], a[3] = {'a', 'b', 'c'};
        unhex("a9993e364706816aba3e25717850c26c9cd0d89d", e);
        c277_sha1(a, 3, o); CHECK(memcmp(o, e, 20) == 0);
        CHECK(c277_crc32_update(0, (const u8 *)"123456789", 9) == 0xCBF43926UL);
        { /* RFC 2202 case 2 */
            unhex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", e);
            c277_hmac_sha1_init(&hc, (const u8 *)"Jefe", 4);
            c277_hmac_sha1_update(&hc, (const u8 *)"what do ya want for nothing?", 28);
            c277_hmac_sha1_final(&hc, o);
            CHECK(memcmp(o, e, 20) == 0);
        }
    }
    { /* NIST SP800-38A F.5.5 CTR-AES256, first block */
        u8 key[32], ctr[16], pt[16], ct[16], e[16];
        unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
        unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr);
        unhex("6bc1bee22e409f96e93d7e117393172a", pt);
        unhex("601ec313775789a5b7a7f504bbf3d228", e);
        c277_aes256_ctr(key, ctr, pt, ct, 16);
        CHECK(memcmp(ct, e, 16) == 0);
    }
    data(key32, 32, 5, 9);
    {
        static const char nm[4] = {'a', 'b', 'c', 'd'};
        static const u32 ns[4] = {100, 70, 33, 1};
        int j;
        for (j = 0; j < 4; j++) {
            if (j == 0) data(iv, 16, 11, 4);
            else if (j == 1) { memset(iv, 0xAB, 8); memset(iv + 8, 0xFF, 8); }
            else if (j == 2) memset(iv, 0xFF, 16);
            else data(iv, 16, 3, 1);
            data(d, 200, 13, 6);
            c277_aes256_ctr(key32, iv, d, o2, ns[j]);
            sprintf(name, "ctr_%c", nm[j]); XC_EQ(name, o2, ns[j]);
            c277_aes256_ctr(key32, iv, o2, o2, ns[j]);   /* in place round trip */
            CHECK(memcmp(o2, d, ns[j]) == 0);
        }
    }
}

/* ------------------------------------------------------------ messages */
static void test_msg(void)
{
    u8 b[600], o[64];
    c277_slice cs[2], uf, pw;
    c277_cands c;
    int n, a, v;
    u32 po, pl;
    char s[256];
    c277_sdp_cand sd;
    static const char l2[] = "a=candidate:99 1 UDP 5 reflector-12-1.reflector 7 typ relay";

    cs[0].p = (const u8 *)"AAA"; cs[0].len = 3;
    cs[1].p = (const u8 *)"BB";  cs[1].len = 2;
    uf.p = (const u8 *)"abcd"; uf.len = 4;
    pw.p = (const u8 *)"0123456789abcdefghijklmn"; pw.len = 24;
    n = c277_msg_build_candidates(b, sizeof(b), cs, 2, &uf, &pw);
    CHECK(n == 1 + 7 + 6 + 8 + 28);
    CHECK(b[0] == 2 && b[1] == 0 && b[4] == 3 && memcmp(b + 5, "AAA", 3) == 0);
    CHECK(c277_msg_body_size(1, b, (u32)n) == n);
    CHECK(c277_msg_body_size(1, b, (u32)n - 1) == -1);
    CHECK(c277_msg_parse_candidates(b, (u32)n, &c) == 0 && c.n == 2 && c.cand[1].len == 2 &&
          c.ufrag.len == 4 && c.pwd.len == 24 && memcmp(c.pwd.p, "0123456789abcdefghijklmn", 24) == 0);
    CHECK(c277_msg_parse_candidates(b, (u32)n - 1, &c) < 0);
    CHECK(c277_msg_build_candidates(b, 20, cs, 2, &uf, &pw) < 0);

    CHECK(c277_msg_media_state_build(1, 0) == 1 && c277_msg_media_state_build(0, 2) == 4);
    c277_msg_media_state_parse(5, &a, &v); CHECK(a == 1 && v == 2);
    CHECK(c277_msg_body_size(3, b, 0) == 0 && c277_msg_body_size(8, b, 4) == 4 &&
          c277_msg_body_size(8, b, 3) == -1 && c277_msg_body_size(9, b, 1) == 1 &&
          c277_msg_body_size(77, b, 100) == -1 && c277_msg_body_size(5, b, 100) == -1);
    CHECK(c277_msg_wrap_data((const u8 *)"xyz", 3, o, 64) == 5 && o[0] == 0 && o[1] == 3);
    b[0] = 0; b[1] = 4; memcpy(b + 2, "abcdEXTRA", 9);
    CHECK(c277_msg_entry_body(5, b, 20, 0, &po, &pl) == 6 && po == 2 && pl == 4);
    CHECK(c277_msg_entry_body(5, b, 20, 1, &po, &pl) == 20 && po == 0 && pl == 20);
    CHECK(c277_msg_entry_body(7, b, 5, 0, &po, &pl) == -1);

    n = c277_sdp_cand_build(s, sizeof(s), 1, 33554431UL, 3, 4000000000UL, 599, "Ab9z");
    {
        u32 l; u8 *e = xc_get("sdp", &l);
        CHECK(n == (int)l && memcmp(s, e, l) == 0);
    }
    CHECK(c277_sdp_cand_parse(s, (u32)n, &sd) == 0 && sd.id == 3 && sd.tag == 4000000000UL &&
          sd.port == 599 && sd.priority == 33554431UL);
    CHECK(c277_sdp_cand_parse(l2, (u32)strlen(l2), &sd) == 0 && sd.id == 12 && sd.tag == 1 && sd.port == 7);
    CHECK(c277_sdp_cand_parse("candidate:1 1 udp 5 10.0.0.1 99 typ host", 40, &sd) < 0);
    CHECK(c277_sdp_cand_parse("candidate:1 1 tcp 5 reflector-1-2.reflector 99 typ relay", 56, &sd) < 0);
    CHECK(c277_sdp_cand_parse("candidate:1 1 udp 5 reflector-1-2.reflector 99 typ srflx", 56, &sd) < 0);
    CHECK(c277_sdp_cand_parse("candidate:1 2 udp 5 reflector-1-2.reflector 99 typ relay", 56, &sd) < 0);
    CHECK(c277_sdp_cand_build(s, 20, 1, 2, 3, 4, 5, "x") < 0);
}

/* ------------------------------------------------------------ reflector */
static void test_refl(void)
{
    u8 tag[16], o[100], own[16];
    u8 pay[20];
    c277_refl_rx rx;
    c277_id64 ids[4];
    char h[64];
    int i, n;
    static const int plens[4] = {0, 1, 5, 20};
    char name[32];

    for (i = 0; i < 16; i++) tag[i] = (u8)(0xA0 + i);
    CHECK(c277_refl_build_hello(tag, 0x01020304UL, o, 40) == 40);
    XC_EQ("refl_hello", o, 40);
    CHECK(o[12] == 4 && o[15] == 1 && o[39] == 0x7B);
    CHECK(c277_refl_build_hello(tag, 1, o, 39) < 0);
    c277_refl_own_tag(tag, 0x01020304UL, own);
    CHECK(memcmp(own, o, 16) == 0);
    for (i = 0; i < 4; i++) {
        data(pay, 20, 9, 7);
        n = c277_refl_wrap(tag, 0xDEADBEEFUL, 0x01020304UL, pay, (u32)plens[i], o, sizeof(o));
        sprintf(name, "refl_wrap_%d", plens[i]);
        XC_EQ(name, o, n);
        CHECK(n == 24 + ((plens[i] + 3) & ~3));
    }
    CHECK(c277_refl_wrap(tag, 1, 2, pay, 20, o, 40) < 0);
    /* parse: server-side view of an incoming frame: tag12 | ownRT | senderRT | len | payload */
    memcpy(o, tag, 12); o[12] = 4; o[13] = 3; o[14] = 2; o[15] = 1;
    o[16] = 0xEF; o[17] = 0xBE; o[18] = 0xAD; o[19] = 0xDE; o[20] = 0; o[21] = 0; o[22] = 0; o[23] = 5;
    memcpy(o + 24, "hello", 5); memset(o + 29, 0, 3);
    c277_refl_parse(o, 32, tag, &rx);
    CHECK(rx.kind == C277_REFL_DATA && rx.sender_tag == 0xDEADBEEFUL && rx.payload_len == 5 &&
          memcmp(rx.payload, "hello", 5) == 0 && !rx.control);
    o[23] = 9;                                  /* len > size-24 */
    c277_refl_parse(o, 32, tag, &rx); CHECK(rx.kind == C277_REFL_READY);
    o[23] = 5; o[0] ^= 1;                       /* wrong tag */
    c277_refl_parse(o, 32, tag, &rx); CHECK(rx.kind == C277_REFL_NONE);
    c277_refl_parse(o, 15, tag, &rx); CHECK(rx.kind == C277_REFL_NONE);
    o[0] ^= 1;
    memset(o + 16, 0xFF, 12);                   /* control reply */
    c277_refl_parse(o, 40, tag, &rx); CHECK(rx.kind == C277_REFL_READY && rx.control);
    c277_refl_parse(o, 16, tag, &rx); CHECK(rx.kind == C277_REFL_READY);

    n = c277_refl_hostname(h, sizeof(h), 2, 777);
    CHECK(n == 25 && memcmp(h, "reflector-2-777.reflector", 25) == 0);
    ids[0].hi = 0; ids[0].lo = 500;
    ids[1].hi = -1; ids[1].lo = 5;              /* negative id sorts first */
    ids[2].hi = 0; ids[2].lo = 100;
    ids[3].hi = 1; ids[3].lo = 0;
    CHECK(c277_refl_rank(ids, 4, 1) == 1 && c277_refl_rank(ids, 4, 2) == 2 &&
          c277_refl_rank(ids, 4, 0) == 3 && c277_refl_rank(ids, 4, 3) == 4);
}

/* ------------------------------------------------------------ STUN */
static void test_stun(void)
{
    static const char *PW = "VOkJxbRl1RmTxUk/WvJxBt";
    c277_stun_msg m;
    u8 b[200], tx[12], tb[8], bad[200];
    int i, n;
    u32 l; u8 *e;
    static const u8 TXB[12] = {0xb7,0xe7,0xa7,0x01,0xbc,0x34,0xd6,0x86,0xfa,0x87,0xdf,0xae};

    /* RFC 5769 2.1 request */
    CHECK(c277_stun_is_stun(RFC5769_REQ, sizeof(RFC5769_REQ)));
    CHECK(c277_stun_parse(RFC5769_REQ, sizeof(RFC5769_REQ), &m) == 0);
    CHECK(m.type == 1 && memcmp(m.txid, TXB, 12) == 0 && m.username_len == 9 &&
          memcmp(m.username, "evtj:h6vY", 9) == 0 && m.has_priority && m.priority == 0x6e0001ffUL &&
          m.controlled && !m.controlling && m.tiebreak[0] == 0x93 && m.tiebreak[7] == 0x36 && !m.use_candidate);
    CHECK(m.mi_off == 76 && m.fp_off == 100);
    CHECK(c277_stun_check_fingerprint(RFC5769_REQ, sizeof(RFC5769_REQ), &m));
    CHECK(c277_stun_check_integrity(RFC5769_REQ, sizeof(RFC5769_REQ), &m, (const u8 *)PW, (u32)strlen(PW)));
    CHECK(!c277_stun_check_integrity(RFC5769_REQ, sizeof(RFC5769_REQ), &m, (const u8 *)"VOkJxbRl1RmTxUk/WvJxBu", 22));
    memcpy(bad, RFC5769_REQ, sizeof(RFC5769_REQ)); bad[30] ^= 1;
    CHECK(c277_stun_parse(bad, sizeof(RFC5769_REQ), &m) == 0 &&
          !c277_stun_check_fingerprint(bad, sizeof(RFC5769_REQ), &m) &&
          !c277_stun_check_integrity(bad, sizeof(RFC5769_REQ), &m, (const u8 *)PW, 22));
    CHECK(c277_stun_parse(RFC5769_REQ, sizeof(RFC5769_REQ) - 1, &m) < 0);
    /* 2.2 IPv4 response */
    CHECK(c277_stun_parse(RFC5769_RESP4, sizeof(RFC5769_RESP4), &m) == 0);
    CHECK(m.type == 0x0101 && m.has_mapped && m.mapped_ip == 0xC0000201UL && m.mapped_port == 32853);
    CHECK(c277_stun_check_fingerprint(RFC5769_RESP4, sizeof(RFC5769_RESP4), &m));
    CHECK(c277_stun_check_integrity(RFC5769_RESP4, sizeof(RFC5769_RESP4), &m, (const u8 *)PW, 22));
    /* 2.3 IPv6 response (address family 2: not reported, hashes still verify) */
    CHECK(c277_stun_parse(RFC5769_RESP6, sizeof(RFC5769_RESP6), &m) == 0 && !m.has_mapped);
    CHECK(c277_stun_check_fingerprint(RFC5769_RESP6, sizeof(RFC5769_RESP6), &m));
    CHECK(c277_stun_check_integrity(RFC5769_RESP6, sizeof(RFC5769_RESP6), &m, (const u8 *)PW, 22));

    /* our builders vs Python */
    for (i = 0; i < 12; i++) tx[i] = (u8)(0x30 + i);
    for (i = 0; i < 8; i++) tb[i] = (u8)(1 + i);
    n = c277_stun_build_request(b, sizeof(b), tx, (const u8 *)"abcd:wxyz", 9, 0x7E0000FFUL, 1, tb, 1,
                                (const u8 *)"0123456789abcdefghijklmn", 24);
    XC_EQ("stun_req_ctl", b, n);
    CHECK(c277_stun_parse(b, (u32)n, &m) == 0 && m.controlling && m.use_candidate && m.priority == 0x7E0000FFUL);
    CHECK(c277_stun_check_fingerprint(b, (u32)n, &m) &&
          c277_stun_check_integrity(b, (u32)n, &m, (const u8 *)"0123456789abcdefghijklmn", 24));
    n = c277_stun_build_request(b, sizeof(b), tx, (const u8 *)"abcd:wxyz", 9, 0x7E0000FFUL, 0, tb, 0,
                                (const u8 *)"0123456789abcdefghijklmn", 24);
    XC_EQ("stun_req_cld", b, n);
    n = c277_stun_build_success(b, sizeof(b), tx, 0, 0x5BA3C801UL, 54321, (const u8 *)"pwdpwdpwdpwdpwdpwdpwdp", 22);
    XC_EQ("stun_ok", b, n);
    CHECK(c277_stun_parse(b, (u32)n, &m) == 0 && m.mapped_ip == 0x5BA3C801UL && m.mapped_port == 54321 &&
          c277_stun_check_integrity(b, (u32)n, &m, (const u8 *)"pwdpwdpwdpwdpwdpwdpwdp", 22));
    n = c277_stun_build_success(b, sizeof(b), tx, "Telegram ", 0x5BA3C801UL, 54321, (const u8 *)"k", 1);
    e = xc_get("stun_ok_sw", &l);
    CHECK(n == (int)l && memcmp(e, b, l) == 0);
    CHECK(c277_stun_build_request(b, 50, tx, (const u8 *)"abcd:wxyz", 9, 1, 1, tb, 1, (const u8 *)"k", 1) < 0);
    CHECK(!c277_stun_is_stun(RFC5769_REQ, 19));
    CHECK(!c277_stun_is_stun((const u8 *)"\x80\x00\x00\x00\x21\x12\xa4\x42xxxxxxxxxxxxxx", 22));
}

/* ------------------------------------------------------------ conn */
typedef struct { int n; int type[16]; u8 body[16][64]; u32 blen[16]; } sink;

static void collect(void *user, int type, const u8 *body, u32 blen)
{
    sink *s = (sink *)user;
    if (s->n < 16) {
        s->type[s->n] = type;
        s->blen[s->n] = blen;
        memcpy(s->body[s->n], body, blen > 64 ? 64 : blen);
        s->n++;
    }
}

static u8 KEYK[256];

static void test_conn_vectors(void)
{
    c277_conn a, as, bs;
    u8 pkt[2048], pt[2048], rtp[20], body[600], *e;
    u32 l, bl;
    int n, i;
    sink s;
    c277_slice cs, uf, pw;
    static const u8 *dummy = 0;

    (void)dummy;
    for (i = 0; i < 256; i++) KEYK[i] = (u8)((i * 5 + 1) & 255);
    for (i = 0; i < 20; i++) rtp[i] = (u8)(0x10 + i);
    c277_conn_init(&a, KEYK, 1, 0);

    n = c277_conn_build(&a, 0, 5, rtp, 20, 0, pkt, sizeof(pkt));
    XC_EQ("conn_a1", pkt, n); CHECK(n == 16 + 25);
    n = c277_conn_build(&a, 10, 4, (const u8 *)"\x01", 1, 1, pkt, sizeof(pkt));
    XC_EQ("conn_a2", pkt, n); CHECK(c277_conn_pending(&a) == 1);

    e = xc_get("conn_b1", &l);
    memset(&s, 0, sizeof(s));
    CHECK(c277_conn_parse(&a, 20, e, l, pt, collect, &s) == 0);
    CHECK(s.n == 1 && s.type[0] == 8 && s.blen[0] == 4 && s.body[0][2] == 3 && s.body[0][3] == 0xE8);
    CHECK(c277_conn_acks_queued(&a) == 1 && c277_conn_next_deadline(&a, 20) == 0);
    CHECK(c277_conn_parse(&a, 21, e, l, pt, collect, &s) == C277_ERR_REPLAY);
    n = c277_conn_build(&a, 30, 5, rtp, 20, 0, pkt, sizeof(pkt));
    XC_EQ("conn_a3", pkt, n); CHECK(c277_conn_acks_queued(&a) == 0);
    n = c277_conn_build(&a, 400, 5, rtp, 20, 0, pkt, sizeof(pkt));
    XC_EQ("conn_a4", pkt, n);
    CHECK(c277_conn_pending(&a) == 1);
    e = xc_get("conn_b2", &l);
    memset(&s, 0, sizeof(s));
    CHECK(c277_conn_parse(&a, 410, e, l, pt, collect, &s) == 0 && s.n == 0 && c277_conn_pending(&a) == 0);
    CHECK(c277_conn_next_deadline(&a, 410) == 0xFFFFFFFFUL);

    /* tampering / short / format */
    e = xc_get("conn_b1", &l);
    memcpy(pkt, e, l); pkt[20] ^= 1;
    { c277_conn t; c277_conn_init(&t, KEYK, 1, 0);
      CHECK(c277_conn_parse(&t, 0, pkt, l, pt, collect, &s) == C277_ERR_MAC);
      CHECK(c277_conn_parse(&t, 0, pkt, 20, pt, collect, &s) == C277_ERR_SHORT);
      /* wrong role: same packet read with the sender's own x */
      c277_conn_init(&t, KEYK, 0, 0);
      CHECK(c277_conn_parse(&t, 0, e, l, pt, collect, &s) == C277_ERR_MAC); }

    /* signalling: build candidates, compare; parse peer VideoFormats (skipped but acked) */
    c277_conn_init(&as, KEYK, 1, 1);
    cs.p = (const u8 *)"x"; cs.len = 0;
    e = xc_get("conn_sig_body", &bl);
    memcpy(body, e, bl);
    {
        c277_cands cc;
        CHECK(c277_msg_parse_candidates(body, bl, &cc) == 0 && cc.n == 1);
        cs = cc.cand[0]; uf = cc.ufrag; pw = cc.pwd;
        n = c277_msg_build_candidates(pkt, sizeof(pkt), &cs, 1, &uf, &pw);
        CHECK((u32)n == bl && memcmp(pkt, body, bl) == 0);
    }
    n = c277_conn_build(&as, 0, 1, body, bl, 1, pkt, sizeof(pkt));
    XC_EQ("conn_sig1", pkt, n);
    CHECK(c277_conn_next_deadline(&as, 0) == 5000);
    CHECK(c277_conn_tick(&as, 4999, pkt, sizeof(pkt)) == 0);
    n = c277_conn_tick(&as, 5001, pkt, sizeof(pkt));
    CHECK(n > 0);   /* dedicated empty packet carrying the resend */
    c277_conn_init(&bs, KEYK, 0, 1);
    memset(&s, 0, sizeof(s));
    CHECK(c277_conn_parse(&bs, 5001, pkt, (u32)n, pt, collect, &s) == 0 &&
          s.n == 1 && s.type[0] == 1 && s.blen[0] == bl);
    e = xc_get("conn_sigpeer", &l);
    memset(&s, 0, sizeof(s));
    CHECK(c277_conn_parse(&as, 6000, e, l, pt, collect, &s) == 0 && s.n == 1 && s.type[0] == 2);
    CHECK(c277_conn_acks_queued(&as) == 1);
    n = c277_conn_tick(&as, 6001, pkt, sizeof(pkt)); CHECK(n > 0);   /* ack_now */
    CHECK(c277_conn_acks_queued(&as) == 0);
}

/* in-memory link */
#define LINKQ 512
typedef struct { u32 t; int len; u8 d[1500]; } lpkt;
typedef struct { lpkt q[LINKQ]; int n; int loss_pct, dup_pct, jit; } link_t;

static u32 rng_state = 12345;
static u32 rnd(void) { rng_state = rng_state * 1664525UL + 1013904223UL; return rng_state >> 8; }

static void link_send(link_t *l, u32 now, const u8 *p, int n)
{
    int copies = 1, c;
    if ((int)(rnd() % 100) < l->loss_pct) return;
    if ((int)(rnd() % 100) < l->dup_pct) copies = 2;
    for (c = 0; c < copies && l->n < LINKQ; c++) {
        l->q[l->n].t = now + rnd() % (u32)l->jit;
        l->q[l->n].len = n;
        memcpy(l->q[l->n].d, p, (size_t)n);
        l->n++;
    }
}

typedef struct {
    int rel_got[64]; int n_rel;       /* reliable ids delivered (can detect dups) */
    int audio_seen[4096]; int audio_dups, audio_n;
} rxstate;

static void rx_cb(void *user, int type, const u8 *body, u32 blen)
{
    rxstate *r = (rxstate *)user;
    if (type == 4 && blen == 1) { if (r->n_rel < 64) r->rel_got[r->n_rel++] = body[0]; }
    else if (type == 5 && blen == 20) {
        int idx = body[0] | (body[1] << 8);
        if (idx < 4096) { if (r->audio_seen[idx]) r->audio_dups++; r->audio_seen[idx] = 1; r->audio_n++; }
    }
}

static void deliver(link_t *l, u32 now, c277_conn *dst, rxstate *rx, int *errs)
{
    int i;
    u8 pt[2048];
    for (i = 0; i < l->n; ) {
        if ((int)(now - l->q[i].t) >= 0) {
            int r = c277_conn_parse(dst, now, l->q[i].d, (u32)l->q[i].len, pt, rx_cb, rx);
            if (r == C277_ERR_REPLAY) errs[0]++;
            else if (r != 0) errs[1]++;
            l->q[i] = l->q[--l->n];
        } else i++;
    }
}

static void sim(int channel_sig, int loss, int dup, int jit)
{
    c277_conn A, B;
    link_t *ab = (link_t *)calloc(1, sizeof(link_t)), *ba = (link_t *)calloc(1, sizeof(link_t));
    rxstate *ra = (rxstate *)calloc(1, sizeof(rxstate)), *rb = (rxstate *)calloc(1, sizeof(rxstate));
    u8 pkt[1500], rtp[20];
    u32 now;
    int next_rel_a = 0, next_rel_b = 0, errs[2] = {0, 0}, n, i, aud = 0;
    int want_a = 20, want_b = 20;

    c277_conn_init(&A, KEYK, 1, channel_sig);
    c277_conn_init(&B, KEYK, 0, channel_sig);
    ab->loss_pct = ba->loss_pct = loss; ab->dup_pct = ba->dup_pct = dup; ab->jit = ba->jit = jit;
    for (now = 0; now < 200000UL; now += 10) {
        if (now < 20000UL && now % 20 == 0) {            /* audio each way, 50 pps */
            rtp[0] = (u8)aud; rtp[1] = (u8)(aud >> 8);
            for (i = 2; i < 20; i++) rtp[i] = (u8)i;
            aud++;
            n = c277_conn_build(&A, now, 5, rtp, 20, 0, pkt, sizeof(pkt)); link_send(ab, now, pkt, n);
            n = c277_conn_build(&B, now, 5, rtp, 20, 0, pkt, sizeof(pkt)); link_send(ba, now, pkt, n);
        }
        if (now % 700 == 0) {                            /* reliable messages */
            u8 id;
            if (next_rel_a < want_a && c277_conn_pending(&A) < C277_MAX_PEND) {
                id = (u8)next_rel_a++;
                n = c277_conn_build(&A, now, 4, &id, 1, 1, pkt, sizeof(pkt)); link_send(ab, now, pkt, n);
            }
            if (next_rel_b < want_b && c277_conn_pending(&B) < C277_MAX_PEND) {
                id = (u8)next_rel_b++;
                n = c277_conn_build(&B, now, 4, &id, 1, 1, pkt, sizeof(pkt)); link_send(ba, now, pkt, n);
            }
        }
        deliver(ab, now, &B, rb, errs);
        deliver(ba, now, &A, ra, errs);
        n = c277_conn_tick(&A, now, pkt, sizeof(pkt)); if (n > 0) link_send(ab, now, pkt, n);
        n = c277_conn_tick(&B, now, pkt, sizeof(pkt)); if (n > 0) link_send(ba, now, pkt, n);
    }
    printf("sim sig=%d loss=%d dup=%d jit=%d: A->B rel=%d/%d B->A rel=%d/%d audio B=%d ra=%d pend A=%d B=%d replays=%d bad=%d\n",
           channel_sig, loss, dup, jit, rb->n_rel, want_a, ra->n_rel, want_b, rb->audio_n, ra->audio_n,
           c277_conn_pending(&A), c277_conn_pending(&B), errs[0], errs[1]);
    CHECK(rb->n_rel == want_a && ra->n_rel == want_b);       /* exactly once */
    for (i = 0; i < want_a; i++) { CHECK(rb->rel_got[i] >= 0); }
    {   /* every id present exactly once (order may vary) */
        int seen[64], j;
        memset(seen, 0, sizeof(seen));
        for (j = 0; j < rb->n_rel; j++) seen[rb->rel_got[j]]++;
        for (j = 0; j < want_a; j++) CHECK(seen[j] == 1);
        memset(seen, 0, sizeof(seen));
        for (j = 0; j < ra->n_rel; j++) seen[ra->rel_got[j]]++;
        for (j = 0; j < want_b; j++) CHECK(seen[j] == 1);
    }
    CHECK(c277_conn_pending(&A) == 0 && c277_conn_pending(&B) == 0);
    CHECK(rb->audio_dups == 0 && ra->audio_dups == 0);
    CHECK(errs[1] == 0);
    CHECK(rb->audio_n > aud * (100 - loss) / 100 * 7 / 10);   /* most audio survives (reorder window drops some) */
    free(ab); free(ba); free(ra); free(rb);
}

static void test_conn_sim(void)
{
    sim(0, 0, 0, 1);
    sim(0, 25, 10, 120);
    sim(1, 25, 10, 120);
    sim(0, 40, 20, 300);
    sim(1, 10, 30, 2000);
}

static void test_conn_misc(void)
{
    c277_conn a, b;
    u8 pkt[1500], pt[1500], big[600];
    sink s;
    int n, i;

    c277_conn_init(&a, KEYK, 1, 0);
    c277_conn_init(&b, KEYK, 0, 0);
    /* reliable queue limit, oversize */
    memset(big, 0, sizeof(big));
    CHECK(c277_conn_build(&a, 0, 4, big, 1, 1, pkt, 20) == C277_ERR_FULL);
    CHECK(c277_conn_build(&a, 0, 7, big, 600, 1, pkt, sizeof(pkt)) == C277_ERR_FULL);   /* > PEND_BYTES */
    for (i = 0; i < C277_MAX_PEND; i++) CHECK(c277_conn_build(&a, 0, 4, big, 1, 1, pkt, sizeof(pkt)) > 0);
    CHECK(c277_conn_build(&a, 0, 4, big, 1, 1, pkt, sizeof(pkt)) == C277_ERR_FULL);
    CHECK(c277_conn_pending(&a) == C277_MAX_PEND);
    /* a reliable packet with ack-needed message: B acks immediately */
    c277_conn_init(&a, KEYK, 1, 0);
    n = c277_conn_build(&a, 0, 4, (const u8 *)"\x01", 1, 1, pkt, sizeof(pkt));
    memset(&s, 0, sizeof(s));
    CHECK(c277_conn_parse(&b, 1, pkt, (u32)n, pt, collect, &s) == 0 && s.n == 1);
    CHECK(c277_conn_parse(&b, 2, pkt, (u32)n, pt, collect, &s) == C277_ERR_REPLAY);
    n = c277_conn_tick(&b, 3, pkt, sizeof(pkt)); CHECK(n > 0);
    CHECK(c277_conn_parse(&a, 4, pkt, (u32)n, pt, collect, &s) == 0 && c277_conn_pending(&a) == 0);
    /* unknown type inside a valid MAC packet is rejected as FORMAT, no callbacks */
    {
        u8 *p = pkt + 16;
        p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 9; p[4] = 99;
        c277_seal(KEYK, 0, p, 5);
        memset(&s, 0, sizeof(s));
        CHECK(c277_conn_parse(&b, 5, pkt, 21, pt, collect, &s) == C277_ERR_FORMAT && s.n == 0);
        /* Ack as first entry is invalid */
        p[3] = 10; p[4] = 0xFF; c277_seal(KEYK, 0, p, 5);
        CHECK(c277_conn_parse(&b, 5, pkt, 21, pt, collect, &s) == C277_ERR_FORMAT);
        /* Empty not first is invalid: seq|type4 body | seq|FE */
        p[3] = 11; p[4] = 4; p[5] = 1; p[6] = 0; p[7] = 0; p[8] = 0; p[9] = 12; p[10] = 0xFE;
        c277_seal(KEYK, 0, p, 11);
        CHECK(c277_conn_parse(&b, 5, pkt, 16 + 11, pt, collect, &s) == C277_ERR_FORMAT);
    }
}

int main(int argc, char **argv)
{
    FILE *f;
    static char buf[200000];
    size_t n;
    if (argc < 2) { printf("usage: test_call277 crosscheck.txt\n"); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) return 2;
    n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0; fclose(f);
    g_xc = buf;
    test_prims();
    test_msg();
    test_refl();
    test_stun();
    test_conn_vectors();
    test_conn_misc();
    test_conn_sim();
    printf("%d checks, %d failed\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
