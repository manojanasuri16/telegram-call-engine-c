/* c277_conn.c - see c277_conn.h. Source: tgcalls EncryptedConnection.cpp (pin
 * 545f5ae), via docs/CALL-277-SPEC.md sec. 3. */
#include <string.h>
#include "c277_conn.h"

#define LATER(a, b) (((int)((a) - (b))) >= 0)   /* a >= b, wrap-safe */

static void w32(u8 *p, u32 v)
{
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}

static u32 r32(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

void c277_conn_init(c277_conn *c, const u8 *K, int is_outgoing, int signaling)
{
    memset(c, 0, sizeof(*c));
    memcpy(c->key, K, 256);
    /* pin EncryptedConnection.cpp:124,172,412-420 */
    c->x_send = (u32)((is_outgoing ? 0 : 8) + (signaling ? 128 : 0));
    c->x_recv = (u32)((is_outgoing ? 8 : 0) + (signaling ? 128 : 0));
    c->signaling = signaling;
    c->min_resend = signaling ? 3000UL : 300UL;     /* pin:786-800 */
    c->max_resend = signaling ? 5000UL : 1000UL;
    c->ack_delay  = signaling ? 5000UL : 1000UL;
    c->max_packet = signaling ? 16384UL : 1452UL;
}

/* ---- replay windows (pin:431-453: reject if seen or counter+64 <= largest) */

static int win_seen(const c277_win *w, u32 c)
{
    u32 d;
    if (!w->have || c > w->largest) return 0;
    d = w->largest - c;
    if (d >= 64) return 1;
    return (d < 32 ? (w->lo >> d) : (w->hi >> (d - 32))) & 1;
}

static void win_add(c277_win *w, u32 c)
{
    u32 d;
    if (!w->have) { w->have = 1; w->largest = c; w->lo = 1; w->hi = 0; return; }
    if (c > w->largest) {
        d = c - w->largest;
        if (d >= 64) { w->lo = 0; w->hi = 0; }
        else if (d >= 32) { w->hi = w->lo << (d - 32); w->lo = 0; }
        else { w->hi = (w->hi << d) | (w->lo >> (32 - d)); w->lo <<= d; }
        w->lo |= 1;
        w->largest = c;
        return;
    }
    d = w->largest - c;
    if (d >= 64) return;
    if (d < 32) w->lo |= 1UL << d; else w->hi |= 1UL << (d - 32);
}

/* Delivered reliable messages: a window keyed on the shared counter would drop
 * legitimately late resends (the counter also advances with every audio packet),
 * so remember the last C277_MSG_SEEN delivered counters instead (pin:744 keeps a list). */
static int msg_seen(const c277_conn *c, u32 ctr)
{
    int i;
    for (i = 0; i < c->msg_nseen; i++) if (c->msg_seen[i] == ctr) return 1;
    return 0;
}

static void msg_add(c277_conn *c, u32 ctr)
{
    c->msg_seen[c->msg_head] = ctr;
    c->msg_head = (c->msg_head + 1) % C277_MSG_SEEN;
    if (c->msg_nseen < C277_MSG_SEEN) c->msg_nseen++;
}

/* ---------------------------------------------------------------- build */

int c277_conn_build(c277_conn *c, u32 now, int type, const u8 *body, u32 blen, int reliable,
                    u8 *out, u32 cap)
{
    u32 limit = cap < c->max_packet ? cap : c->max_packet;
    u32 room, pos = 0, seq, ent_len = 0, i, k;
    int single, framed, due0;
    u8 *pt;

    if (limit < 16 + 5) return C277_ERR_FULL;
    pt = out + 16;
    room = limit - 16;
    framed = type >= 0 && c277_msg_is_data(type);

    /* validate before touching state */
    if (type >= 0) {
        ent_len = 5 + blen + (framed ? 2 : 0);
        if (type > 0xFD || blen > 65535UL) return C277_ERR_FULL;
        if (ent_len > room) return C277_ERR_FULL;
        if (reliable && (c->npend >= C277_MAX_PEND || ent_len > C277_PEND_BYTES))
            return C277_ERR_FULL;
    }

    due0 = c->npend > 0 && LATER(now, c->pend[0].last_sent + c->min_resend);
    /* single-message packet (pin:286): exactly one non-ack-required message,
     * nothing else to append */
    single = type >= 0 && !reliable && c->nacks == 0 && !due0;

    seq = (++c->counter) & C277_SEQ_MASK;
    if (single) {
        w32(pt, seq | C277_SEQ_SINGLE);
        pt[4] = (u8)type;
        if (blen) memcpy(pt + 5, body, blen);   /* single: data rest-of-packet, no u16 */
        pos = 5 + blen;
        c277_seal(c->key, c->x_send, pt, pos);
        return (int)(16 + pos);
    }

    if (type < 0) {
        w32(pt, seq);
        pt[4] = C277_MSG_EMPTY;
        pos = 5;
    } else {
        if (reliable) seq |= C277_SEQ_ACKREQ;
        w32(pt, seq);
        pt[4] = (u8)type;
        pos = 5;
        if (framed) { pt[pos++] = (u8)(blen >> 8); pt[pos++] = (u8)blen; }
        if (blen) memcpy(pt + pos, body, blen);
        pos += blen;
    }

    /* due resends, in order, stop at first not-due or non-fitting (pin:332-400) */
    for (i = 0; i < (u32)c->npend; i++) {
        if (!LATER(now, c->pend[i].last_sent + c->min_resend)) break;
        if (c->pend[i].len > room - pos) break;
        memcpy(pt + pos, c->pend[i].data, c->pend[i].len);
        pos += c->pend[i].len;
        c->pend[i].last_sent = now;
    }

    /* acks: ackedSeq u32 | FF */
    for (k = 0; k < (u32)c->nacks; k++) {
        if (room - pos < 5) break;
        w32(pt + pos, c->acks[k]);
        pt[pos + 4] = C277_MSG_ACK;
        pos += 5;
    }
    if (k) {
        memmove(c->acks, c->acks + k, (c->nacks - k) * sizeof(u32));
        c->nacks -= (int)k;
    }
    if (c->nacks == 0) c->ack_now = 0;
    else c->ack_since = now;

    if (type >= 0 && reliable) {
        c277_pend *p = &c->pend[c->npend++];
        p->seq = seq;
        p->last_sent = now;
        p->len = ent_len;
        memcpy(p->data, pt, 5);                   /* seq | type */
        i = 5;
        if (framed) { p->data[i++] = (u8)(blen >> 8); p->data[i++] = (u8)blen; }
        if (blen) memcpy(p->data + i, body, blen);
    }
    c277_seal(c->key, c->x_send, pt, pos);
    return (int)(16 + pos);
}

/* ---------------------------------------------------------------- parse */

typedef struct {
    u32 word;
    int type;
    u32 body_off, body_len;   /* payload within pt */
    u32 next;
} entry;

static int next_entry(const u8 *pt, u32 n, u32 pos, int first, int single, entry *e)
{
    int used;
    u32 poff, plen;
    if (n - pos < 5) return -1;
    e->word = r32(pt + pos);
    e->type = pt[pos + 4];
    pos += 5;
    e->body_off = pos; e->body_len = 0;
    if (e->type == C277_MSG_ACK) {
        if (first || single) return -1;
    } else if (e->type == C277_MSG_EMPTY) {
        if (!first || single) return -1;
    } else {
        used = c277_msg_entry_body(e->type, pt + pos, n - pos, single, &poff, &plen);
        if (used < 0) return -1;
        e->body_off = pos + poff;
        e->body_len = plen;
        pos += (u32)used;
    }
    e->next = pos;
    return 0;
}

static void pend_remove(c277_conn *c, u32 word)
{
    int i;
    for (i = 0; i < c->npend; i++) {
        if (c->pend[i].seq == word) {
            memmove(&c->pend[i], &c->pend[i + 1], (size_t)(c->npend - i - 1) * sizeof(c277_pend));
            c->npend--;
            return;
        }
    }
}

int c277_conn_parse(c277_conn *c, u32 now, const u8 *pkt, u32 len, u8 *pt,
                    c277_msg_cb cb, void *user)
{
    u32 n, pos, ctr0;
    int single, first;
    entry e;

    if (len < 16 + 5) return C277_ERR_SHORT;
    n = len - 16;
    if (c277_open(c->key, c->x_recv, pkt, pkt + 16, n, pt) < 0) return C277_ERR_MAC;

    single = (r32(pt) & C277_SEQ_SINGLE) != 0;
    ctr0 = r32(pt) & C277_SEQ_MASK;
    if (win_seen(&c->pkt_win, ctr0)) return C277_ERR_REPLAY;

    /* pass 1: structure */
    pos = 0; first = 1;
    while (pos < n) {
        if (next_entry(pt, n, pos, first, single, &e) < 0) return C277_ERR_FORMAT;
        pos = e.next;
        first = 0;
        if (single) break;
    }
    if (pos != n) return C277_ERR_FORMAT;

    win_add(&c->pkt_win, ctr0);

    /* pass 2: effects */
    pos = 0; first = 1;
    while (pos < n) {
        next_entry(pt, n, pos, first, single, &e);
        pos = e.next;
        first = 0;
        if (e.type == C277_MSG_ACK) {
            pend_remove(c, e.word);
        } else if (e.type == C277_MSG_EMPTY) {
            /* nothing */
        } else if (e.word & C277_SEQ_ACKREQ) {
            u32 ctr = e.word & C277_SEQ_MASK;
            int dup = msg_seen(c, ctr);
            int i, have = 0;
            for (i = 0; i < c->nacks; i++) if (c->acks[i] == e.word) have = 1;
            /* always ack, even duplicates (pin:526-640, registerSentAck pin:744) */
            if (!have && c->nacks < C277_MAX_ACKS) {
                if (c->nacks == 0) c->ack_since = now;
                c->acks[c->nacks++] = e.word;
            }
            if (!dup) {
                msg_add(c, ctr);
                c->ack_now = 1;
                if (cb) cb(user, e.type, pt + e.body_off, e.body_len);
            }
        } else {
            if (cb) cb(user, e.type, pt + e.body_off, e.body_len);
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- timers */

int c277_conn_tick(c277_conn *c, u32 now, u8 *out, u32 cap)
{
    int need = 0, i;
    if (c->nacks && (c->ack_now || LATER(now, c->ack_since + c->ack_delay))) need = 1;
    for (i = 0; i < c->npend && !need; i++)
        if (LATER(now, c->pend[i].last_sent + c->max_resend)) need = 1;
    if (!need) return 0;
    return c277_conn_build(c, now, -1, 0, 0, 0, out, cap);
}

u32 c277_conn_next_deadline(const c277_conn *c, u32 now)
{
    u32 best = 0xFFFFFFFFUL, d;
    int i;
    if (c->nacks) {
        if (c->ack_now) return 0;
        d = c->ack_since + c->ack_delay - now;
        if ((int)d < 0) d = 0;
        if (d < best) best = d;
    }
    for (i = 0; i < c->npend; i++) {
        d = c->pend[i].last_sent + c->max_resend - now;
        if ((int)d < 0) d = 0;
        if (d < best) best = d;
    }
    return best;
}

int c277_conn_pending(const c277_conn *c) { return c->npend; }
int c277_conn_acks_queued(const c277_conn *c) { return c->nacks; }
