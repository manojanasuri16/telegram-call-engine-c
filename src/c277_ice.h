/* c277_ice.h - minimal ICE agent for ONE path through our reflector
 * (spec sec. 2.3). No sockets, no clock: the caller feeds already unwrapped
 * reflector payloads and drives time (ms, wrap-safe u32). C89, no malloc. */
#ifndef C277_ICE_H
#define C277_ICE_H

#include "c277_stun.h"
#include "c277_msg.h"

#define C277_ICE_RANDOM 44    /* random bytes needed by init: ufrag 4, pwd 24, tiebreak 8, txid seed 8 */
#define C277_ICE_RMAX   64    /* max accepted remote ufrag/pwd length */
#define C277_ICE_NTX    8     /* outstanding binding requests remembered */

#define C277_ICE_IDLE       0   /* no remote credentials + candidate yet */
#define C277_ICE_CHECKING   1   /* sending binding requests */
#define C277_ICE_CONNECTED  2   /* a valid success response was received */
#define C277_ICE_FAILED     3   /* silent too long (revives on any valid response) */

#define C277_ICE_PING_FAST   500UL    /* until the first response */
#define C277_ICE_PING_SLOW   2000UL   /* keep-alive afterwards (spec 2.3 "cadence") */
#define C277_ICE_DEAD_CONN   20000UL  /* no valid packet while connected -> FAILED (spec sec.1 step 8) */
#define C277_ICE_DEAD_CHECK  60000UL  /* no response while checking -> FAILED (my choice) */

typedef struct {
    u8 id[12];
    int used, use_cand;
} c277_ice_tx;

typedef struct {
    int controlling;
    u8  lufrag[4], lpwd[24], tiebreak[8], txseed[8];
    u32 txctr;
    u32 l_id, l_tag, l_port;       /* our reflector candidate */
    u32 refl_ip, refl_port;        /* reflector address, reported in XOR-MAPPED-ADDRESS */
    int have_creds;
    u8  rufrag[C277_ICE_RMAX], rpwd[C277_ICE_RMAX];
    u32 rufrag_len, rpwd_len;
    int have_rtag;                 /* peer's reflector randomTag known */
    u32 r_tag;
    int state, started, ever_resp, nominated;
    u32 start_time, next_ping, last_rx;
    c277_ice_tx tx[C277_ICE_NTX];
    int txhead;
} c277_ice;

/* rnd: C277_ICE_RANDOM bytes. controlling: we are the caller. */
void c277_ice_init(c277_ice *ice, int controlling, const u8 *rnd);

/* Our reflector port: rank id, randomTag, server port; refl_ip/port: reflector address (host order). */
void c277_ice_set_local(c277_ice *ice, u32 id, u32 tag, u32 port, u32 refl_ip, u32 refl_port);

const u8 *c277_ice_ufrag(const c277_ice *ice);   /* 4 bytes */
const u8 *c277_ice_pwd(const c277_ice *ice);     /* 24 bytes */

/* Body of our CandidatesList message (id 1): one relay candidate + ufrag + pwd.
 * Returns length or -1. */
int c277_ice_build_candidates(const c277_ice *ice, u8 *out, u32 cap);

/* Process the body of a received CandidatesList. Credentials: first message wins.
 * Candidates: only `reflector-<ourId>-<tag>.reflector <ourPort>` relay lines are kept
 * (spec sec.1 step 4); host/srflx/other ids are dropped. Returns the number of
 * kept candidates, or -1 on a malformed body. */
int c277_ice_on_candidates(c277_ice *ice, const u8 *body, u32 len);

/* One incoming unwrapped reflector payload that c277_stun_is_stun() accepted.
 * sender_tag: LE32 from the reflector header. If a response must be sent it is
 * built into out and its length returned; 0 otherwise. */
int c277_ice_rx(c277_ice *ice, u32 now, const u8 *d, u32 n, u32 sender_tag, u8 *out, u32 cap);

/* Any other valid packet from the peer (audio, transport) counts as liveness. */
void c277_ice_activity(c277_ice *ice, u32 now);

/* Timer: if a binding request is due, build it into out and return its length, else 0.
 * Also updates FAILED. Call every <= 20 ms. */
int c277_ice_tick(c277_ice *ice, u32 now, u8 *out, u32 cap);

int  c277_ice_state(const c277_ice *ice);
int  c277_ice_nominated(const c277_ice *ice);
int  c277_ice_peer_tag(const c277_ice *ice, u32 *tag);   /* 1 if known */

#endif
