/* c277_conn.h - tgcalls EncryptedConnection (spec sec. 3), C89, no malloc.
 * One instance per channel: SIGNALING (x+128, 5000/3000 ms) and TRANSPORT.
 * The caller owns the struct (about 4.5 KB), all packet buffers, and drives
 * time (ms, wrap-safe u32) through now arguments. */
#ifndef C277_CONN_H
#define C277_CONN_H

#include "c277_msg.h"

#define C277_SEQ_SINGLE 0x80000000UL
#define C277_SEQ_ACKREQ 0x40000000UL
#define C277_SEQ_MASK   0x3FFFFFFFUL

#define C277_MAX_PEND   8     /* unacked reliable messages kept */
#define C277_PEND_BYTES 512   /* max serialized entry (seq|type|body) kept for resend */
#define C277_MAX_ACKS   32

#define C277_ERR_SHORT   (-1)
#define C277_ERR_MAC     (-2)
#define C277_ERR_REPLAY  (-3)
#define C277_ERR_FORMAT  (-4)
#define C277_ERR_FULL    (-5)   /* build: too big / pending queue full */

typedef struct { u32 largest, lo, hi; int have; } c277_win;

#define C277_MSG_SEEN 32   /* delivered reliable counters remembered (sender has <= C277_MAX_PEND outstanding) */

typedef struct {
    u32 seq;            /* full seq word of the stored entry */
    u32 last_sent;
    u32 len;
    u8  data[C277_PEND_BYTES];
} c277_pend;

typedef struct {
    u8  key[256];
    u32 x_send, x_recv;
    int signaling;
    u32 min_resend;     /* 300 transport / 3000 signalling */
    u32 max_resend;     /* 1000 / 5000: dedicated packet after this */
    u32 ack_delay;      /* 1000 / 5000 */
    u32 max_packet;     /* 1452 / 16384 */
    u32 counter;
    c277_win pkt_win;
    u32 msg_seen[C277_MSG_SEEN];   /* ring of delivered ack-required counters */
    int msg_nseen, msg_head;
    c277_pend pend[C277_MAX_PEND];
    int npend;
    u32 acks[C277_MAX_ACKS];
    int nacks;
    int ack_now;
    u32 ack_since;
} c277_conn;

/* Delivery callback. type = message id; body/blen = payload (for data types the
 * raw data without the u16 prefix; e.g. the RTP packet for id 5). Pointers are
 * valid only during the call. */
typedef void (*c277_msg_cb)(void *user, int type, const u8 *body, u32 blen);

/* K: 256-byte call key. is_outgoing: we are the caller. */
void c277_conn_init(c277_conn *c, const u8 *K, int is_outgoing, int signaling);

/* Build one packet into out (cap bytes). type < 0: Empty packet (acks/resends
 * only). Data types 5/6/7: body = raw data. reliable != 0: message gets ACKREQ
 * and is resent until acked. Returns packet length, or C277_ERR_FULL. Pending
 * acks and due resends are appended automatically. */
int c277_conn_build(c277_conn *c, u32 now, int type, const u8 *body, u32 blen, int reliable,
                    u8 *out, u32 cap);

/* Parse a received packet. pt: scratch of at least len-16 bytes (the callback
 * body pointers refer into it). Returns 0, or a C277_ERR_* code. All entries are
 * validated before any state change or callback. */
int c277_conn_parse(c277_conn *c, u32 now, const u8 *pkt, u32 len, u8 *pt,
                    c277_msg_cb cb, void *user);

/* Timer service: if an ack is due or a resend is overdue, builds a dedicated
 * packet into out and returns its length; else 0. Call every <=20 ms. */
int c277_conn_tick(c277_conn *c, u32 now, u8 *out, u32 cap);

/* ms until the next tick action is needed (0 = now), 0xFFFFFFFF if idle. */
u32 c277_conn_next_deadline(const c277_conn *c, u32 now);

int c277_conn_pending(const c277_conn *c);    /* unacked reliable messages */
int c277_conn_acks_queued(const c277_conn *c);

#endif
