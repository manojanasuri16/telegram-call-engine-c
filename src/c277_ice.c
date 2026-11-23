/* c277_ice.c - see c277_ice.h. Behaviour per docs/CALL-277-SPEC.md sec. 2.3. */
#include <string.h>
#include "c277_ice.h"
#include "c277_refl.h"

#define LATER(a, b) (((int)((a) - (b))) >= 0)

/* ICE_UFRAG/PWD alphabet (webrtc: A-Za-z0-9+/) */
static char alpha(u8 r)
{
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return tab[r & 63];
}

void c277_ice_init(c277_ice *ice, int controlling, const u8 *rnd)
{
    int i;
    memset(ice, 0, sizeof(*ice));
    ice->controlling = controlling != 0;
    for (i = 0; i < 4; i++) ice->lufrag[i] = (u8)alpha(rnd[i]);
    for (i = 0; i < 24; i++) ice->lpwd[i] = (u8)alpha(rnd[4 + i]);
    memcpy(ice->tiebreak, rnd + 28, 8);
    memcpy(ice->txseed, rnd + 36, 8);
    ice->state = C277_ICE_IDLE;
}

void c277_ice_set_local(c277_ice *ice, u32 id, u32 tag, u32 port, u32 refl_ip, u32 refl_port)
{
    ice->l_id = id; ice->l_tag = tag; ice->l_port = port;
    ice->refl_ip = refl_ip; ice->refl_port = refl_port;
}

const u8 *c277_ice_ufrag(const c277_ice *ice) { return ice->lufrag; }
const u8 *c277_ice_pwd(const c277_ice *ice) { return ice->lpwd; }

int c277_ice_build_candidates(const c277_ice *ice, u8 *out, u32 cap)
{
    char line[256], uf[5];
    int n;
    c277_slice cs, uf_s, pw_s;
    memcpy(uf, ice->lufrag, 4); uf[4] = 0;
    /* foundation: any digits; priority as the real client (capture)|(0xFFFF<<8)|255 (spec 2.3) */
    n = c277_sdp_cand_build(line, sizeof(line), (ice->l_tag % 1000000UL) + 1, 41878272UL,
                            ice->l_id, ice->l_tag, ice->l_port, uf);
    if (n < 0) return -1;
    cs.p = (const u8 *)line; cs.len = (u32)n;
    uf_s.p = ice->lufrag; uf_s.len = 4;
    pw_s.p = ice->lpwd; pw_s.len = 24;
    return c277_msg_build_candidates(out, cap, &cs, 1, &uf_s, &pw_s);
}

int c277_ice_on_candidates(c277_ice *ice, const u8 *body, u32 len)
{
    c277_cands c;
    c277_sdp_cand sd;
    u32 i, lim, kept = 0;
    if (c277_msg_parse_candidates(body, len, &c) < 0) return -1;
    /* first message wins (NetworkManager.cpp pin:221-232); peer requires ufrag>=4, pwd>=22 */
    if (!ice->have_creds && c.ufrag.len >= 4 && c.ufrag.len <= C277_ICE_RMAX &&
        c.pwd.len >= 22 && c.pwd.len <= C277_ICE_RMAX) {
        memcpy(ice->rufrag, c.ufrag.p, c.ufrag.len); ice->rufrag_len = c.ufrag.len;
        memcpy(ice->rpwd, c.pwd.p, c.pwd.len); ice->rpwd_len = c.pwd.len;
        ice->have_creds = 1;
    }
    lim = c.n < C277_MAX_CANDS ? c.n : C277_MAX_CANDS;
    for (i = 0; i < lim; i++) {
        if (c277_sdp_cand_parse((const char *)c.cand[i].p, c.cand[i].len, &sd) < 0) continue;
        if (sd.id != ice->l_id || sd.port != ice->l_port || sd.tag == 0) continue;
        if (!ice->have_rtag) { ice->have_rtag = 1; ice->r_tag = sd.tag; }
        kept++;
    }
    return (int)kept;
}

/* ------------------------------------------------------------ receive */

static void make_txid(c277_ice *ice, u8 *id)
{
    u32 c = ++ice->txctr;
    memcpy(id, ice->txseed, 8);
    id[8] = (u8)(c >> 24); id[9] = (u8)(c >> 16); id[10] = (u8)(c >> 8); id[11] = (u8)c;
}

static void mark_connected(c277_ice *ice, u32 now)
{
    ice->last_rx = now;
    ice->state = C277_ICE_CONNECTED;
    if (!ice->ever_resp) {
        ice->ever_resp = 1;
        ice->next_ping = now + C277_ICE_PING_SLOW;
    }
}

static int handle_request(c277_ice *ice, u32 now, const u8 *d, u32 n, const c277_stun_msg *m,
                          u32 sender_tag, u8 *out, u32 cap)
{
    /* port.cc:430-482: fingerprint, USERNAME "<ourUfrag>:...", MI keyed with our pwd */
    if (!c277_stun_check_fingerprint(d, n, m)) return 0;
    if (m->username_len < 5 || memcmp(m->username, ice->lufrag, 4) != 0 || m->username[4] != ':')
        return 0;
    if (!c277_stun_check_integrity(d, n, m, ice->lpwd, 24)) return 0;
    /* role conflict: roles are fixed by call direction, ignore (spec 2.3) */
    if ((ice->controlling && m->controlling) || (!ice->controlling && m->controlled)) return 0;
    if (!ice->have_rtag && sender_tag) { ice->have_rtag = 1; ice->r_tag = sender_tag; }
    ice->last_rx = now;
    if (!ice->controlling && m->use_candidate) ice->nominated = 1;
    return c277_stun_build_success(out, cap, m->txid, 0, ice->refl_ip, ice->refl_port, ice->lpwd, 24);
}

static void handle_response(c277_ice *ice, u32 now, const u8 *d, u32 n, const c277_stun_msg *m)
{
    int i;
    if (!ice->have_creds) return;
    for (i = 0; i < C277_ICE_NTX; i++)
        if (ice->tx[i].used && memcmp(ice->tx[i].id, m->txid, 12) == 0) break;
    if (i == C277_ICE_NTX) return;
    if (!c277_stun_check_fingerprint(d, n, m)) return;
    if (!c277_stun_check_integrity(d, n, m, ice->rpwd, ice->rpwd_len)) return;
    if (ice->tx[i].use_cand) ice->nominated = 1;
    mark_connected(ice, now);
}

int c277_ice_rx(c277_ice *ice, u32 now, const u8 *d, u32 n, u32 sender_tag, u8 *out, u32 cap)
{
    c277_stun_msg m;
    int r = 0;
    if (c277_stun_parse(d, n, &m) < 0) return 0;
    if (m.type == C277_STUN_BIND_REQ) {
        r = handle_request(ice, now, d, n, &m, sender_tag, out, cap);
        if (r < 0) r = 0;
    } else if (m.type == C277_STUN_BIND_OK) {
        handle_response(ice, now, d, n, &m);
    }
    return r;
}

void c277_ice_activity(c277_ice *ice, u32 now)
{
    ice->last_rx = now;
    if (ice->state == C277_ICE_FAILED) ice->state = ice->ever_resp ? C277_ICE_CONNECTED : C277_ICE_CHECKING;
}

/* ------------------------------------------------------------ timers */

int c277_ice_tick(c277_ice *ice, u32 now, u8 *out, u32 cap)
{
    u8 user[2 * C277_ICE_RMAX + 2], *id;
    u32 ul;
    int n, uc;
    c277_ice_tx *t;

    if (!ice->have_creds || !ice->have_rtag) return 0;
    if (!ice->started) {
        ice->started = 1; ice->start_time = now; ice->last_rx = now;
        ice->next_ping = now;
        ice->state = C277_ICE_CHECKING;
    }
    if (ice->state != C277_ICE_FAILED) {
        if (ice->ever_resp ? !LATER(ice->last_rx + C277_ICE_DEAD_CONN, now)
                           : !LATER(ice->last_rx + C277_ICE_DEAD_CHECK, now))
            ice->state = C277_ICE_FAILED;   /* keeps pinging at the slow rate */
    }
    if (!LATER(now, ice->next_ping)) return 0;

    memcpy(user, ice->rufrag, ice->rufrag_len);
    ul = ice->rufrag_len;
    user[ul++] = ':';
    memcpy(user + ul, ice->lufrag, 4); ul += 4;

    /* regular nomination: controlling side adds USE-CANDIDATE after the first success */
    uc = ice->controlling && ice->ever_resp;
    t = &ice->tx[ice->txhead];
    ice->txhead = (ice->txhead + 1) % C277_ICE_NTX;
    id = t->id;
    make_txid(ice, id);
    n = c277_stun_build_request(out, cap, id, user, ul, 0x6EFFFFFFUL /* prflx pref 110 */,
                                ice->controlling, ice->tiebreak, uc, ice->rpwd, ice->rpwd_len);
    if (n < 0) { t->used = 0; return 0; }
    t->used = 1; t->use_cand = uc;
    ice->next_ping = now + (ice->ever_resp ? C277_ICE_PING_SLOW : C277_ICE_PING_FAST);
    return n;
}

int c277_ice_state(const c277_ice *ice) { return ice->state; }
int c277_ice_nominated(const c277_ice *ice) { return ice->nominated; }
int c277_ice_peer_tag(const c277_ice *ice, u32 *tag)
{
    if (ice->have_rtag) *tag = ice->r_tag;
    return ice->have_rtag;
}
