/* c277_msg.c - see c277_msg.h. */
#include <string.h>
#include "c277_msg.h"

int c277_msg_is_data(int type)
{
    return type == C277_MSG_AUDIO || type == C277_MSG_VIDEO || type == C277_MSG_UNSTRUCT;
}

/* returns bytes of "u32 len | bytes" at p, or -1 */
static int str_size(const u8 *p, u32 avail)
{
    u32 l;
    if (avail < 4) return -1;
    l = ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
    if (l >= 65536UL) return -1;
    if (avail - 4 < l) return -1;
    return (int)(4 + l);
}

int c277_msg_body_size(int type, const u8 *p, u32 avail)
{
    u32 pos = 0, i, j, n, np;
    int s;
    switch (type) {
    case C277_MSG_REQUESTVIDEO: return 0;
    case C277_MSG_MEDIASTATE:
    case C277_MSG_BATTERY:      return avail >= 1 ? 1 : -1;
    case C277_MSG_VIDEOPARAMS:  return avail >= 4 ? 4 : -1;
    case C277_MSG_NETSTATUS:
        /* Message.cpp (RemoteNetworkStatus): lowCost + lowData; spec marks lowData
         * "optional". V1-only; we take the literal 2-byte form. */
        return avail >= 2 ? 2 : -1;
    case C277_MSG_CANDIDATES:
        if (avail < 1) return -1;
        n = p[pos++];
        for (i = 0; i < n + 2; i++) {   /* n candidates, ufrag, pwd */
            s = str_size(p + pos, avail - pos);
            if (s < 0) return -1;
            pos += (u32)s;
        }
        return (int)pos;
    case C277_MSG_VIDEOFORMATS:
        if (avail < 1) return -1;
        n = p[pos++];
        for (i = 0; i < n; i++) {
            s = str_size(p + pos, avail - pos);
            if (s < 0) return -1;
            pos += (u32)s;
            if (avail - pos < 1) return -1;
            np = p[pos++];
            for (j = 0; j < np * 2; j++) {
                s = str_size(p + pos, avail - pos);
                if (s < 0) return -1;
                pos += (u32)s;
            }
        }
        if (avail - pos < 1) return -1;   /* encodersCount */
        return (int)(pos + 1);
    default:
        return -1;
    }
}

int c277_msg_entry_body(int type, const u8 *p, u32 avail, int single,
                        u32 *payload_off, u32 *payload_len)
{
    int s;
    u32 l;
    if (c277_msg_is_data(type)) {
        if (single) {
            *payload_off = 0; *payload_len = avail;
            return (int)avail;
        }
        if (avail < 2) return -1;
        l = ((u32)p[0] << 8) | p[1];
        if (avail - 2 < l) return -1;
        *payload_off = 2; *payload_len = l;
        return (int)(2 + l);
    }
    s = c277_msg_body_size(type, p, avail);
    if (s < 0) return -1;
    *payload_off = 0; *payload_len = (u32)s;
    return s;
}

int c277_msg_wrap_data(const u8 *data, u32 n, u8 *out, u32 cap)
{
    if (n > 65535UL || cap < n + 2) return -1;
    out[0] = (u8)(n >> 8); out[1] = (u8)n;
    memcpy(out + 2, data, n);
    return (int)(n + 2);
}

static int put_str(u8 *out, u32 cap, u32 pos, const c277_slice *s)
{
    if (s->len >= 65536UL || cap - pos < 4 + s->len) return -1;
    out[pos] = (u8)(s->len >> 24); out[pos + 1] = (u8)(s->len >> 16);
    out[pos + 2] = (u8)(s->len >> 8); out[pos + 3] = (u8)s->len;
    memcpy(out + pos + 4, s->p, s->len);
    return (int)(pos + 4 + s->len);
}

int c277_msg_build_candidates(u8 *out, u32 cap, const c277_slice *cands, u32 n,
                              const c277_slice *ufrag, const c277_slice *pwd)
{
    u32 i;
    int pos;
    if (n > 255 || cap < 1) return -1;
    out[0] = (u8)n;
    pos = 1;
    for (i = 0; i < n; i++) {
        pos = put_str(out, cap, (u32)pos, &cands[i]);
        if (pos < 0) return -1;
    }
    pos = put_str(out, cap, (u32)pos, ufrag);
    if (pos < 0) return -1;
    return put_str(out, cap, (u32)pos, pwd);
}

static int get_str(const u8 *p, u32 len, u32 *pos, c277_slice *s)
{
    int z = str_size(p + *pos, len - *pos);
    if (z < 0) return -1;
    s->p = p + *pos + 4;
    s->len = (u32)z - 4;
    *pos += (u32)z;
    return 0;
}

int c277_msg_parse_candidates(const u8 *b, u32 len, c277_cands *o)
{
    u32 pos = 1, i;
    c277_slice t;
    if (len < 1) return -1;
    o->n = b[0];
    for (i = 0; i < o->n; i++) {
        if (get_str(b, len, &pos, i < C277_MAX_CANDS ? &o->cand[i] : &t) < 0) return -1;
    }
    if (get_str(b, len, &pos, &o->ufrag) < 0) return -1;
    if (get_str(b, len, &pos, &o->pwd) < 0) return -1;
    return pos == len ? 0 : -1;
}

u8 c277_msg_media_state_build(int audio, int video)
{
    return (u8)(((video & 3) << 1) | (audio & 1));
}

void c277_msg_media_state_parse(u8 b, int *audio, int *video)
{
    *audio = b & 1;
    *video = (b >> 1) & 3;
}

/* ------------------------------------------------------------------ SDP */

u32 c277_put_dec(char *out, u32 n)
{
    char t[10];
    u32 l = 0, i;
    do { t[l++] = (char)('0' + n % 10); n /= 10; } while (n);
    for (i = 0; i < l; i++) out[i] = t[l - 1 - i];
    return l;
}

static int app(char *out, u32 cap, u32 *pos, const char *s)
{
    u32 l = (u32)strlen(s);
    if (cap - *pos < l) return -1;
    memcpy(out + *pos, s, l);
    *pos += l;
    return 0;
}

static int appn(char *out, u32 cap, u32 *pos, u32 n)
{
    if (cap - *pos < 10) return -1;   /* conservative */
    *pos += c277_put_dec(out + *pos, n);
    return 0;
}

int c277_sdp_cand_build(char *out, u32 cap, u32 foundation, u32 priority, u32 id, u32 tag,
                        u32 port, const char *ufrag)
{
    u32 p = 0;
    if (app(out, cap, &p, "candidate:") || appn(out, cap, &p, foundation) ||
        app(out, cap, &p, " 0 udp ") || appn(out, cap, &p, priority) ||
        app(out, cap, &p, " reflector-") || appn(out, cap, &p, id) ||
        app(out, cap, &p, "-") || appn(out, cap, &p, tag) ||
        app(out, cap, &p, ".reflector ") || appn(out, cap, &p, port) ||
        app(out, cap, &p, " typ relay generation 0 ufrag ") ||
        app(out, cap, &p, ufrag) ||
        app(out, cap, &p, " network-id 1 network-cost 10"))
        return -1;
    return (int)p;
}

/* parse decimal at s[*i..len) up to terminator; returns 0 ok */
static int dec(const char *s, u32 len, u32 *i, u32 *v)
{
    u32 n = 0, d = 0;
    while (*i < len && s[*i] >= '0' && s[*i] <= '9') {
        if (n > 429496729UL) return -1;
        n = n * 10 + (u32)(s[*i] - '0');
        (*i)++; d++;
    }
    if (!d) return -1;
    *v = n;
    return 0;
}

int c277_sdp_cand_parse(const char *s, u32 len, c277_sdp_cand *o)
{
    u32 st[24], en[24], nt = 0, i = 0, k;
    static const char pre[] = "candidate:";   /* const: not writable data */
    const char *h;
    u32 hl, hi;
    int relay = 0;

    while (i < len && nt < 24) {
        while (i < len && s[i] == ' ') i++;
        if (i >= len) break;
        st[nt] = i;
        while (i < len && s[i] != ' ') i++;
        en[nt++] = i;
    }
    if (nt < 8) return -1;
    k = st[0];
    if (en[0] - k > 2 && s[k] == 'a' && s[k + 1] == '=') k += 2;
    if (en[0] - k < 10 || memcmp(s + k, pre, 10) != 0) return -1;
    if (en[1] - st[1] != 1 || (s[st[1]] != '0' && s[st[1]] != '1')) return -1;   /* real clients send 0 */
    if (en[2] - st[2] != 3 || (s[st[2]] | 0x20) != 'u' || (s[st[2] + 1] | 0x20) != 'd' ||
        (s[st[2] + 2] | 0x20) != 'p') return -1;
    i = st[3];
    if (dec(s, en[3], &i, &o->priority) < 0 || i != en[3]) return -1;
    h = s + st[4]; hl = en[4] - st[4];
    if (hl < 9 + 3 + 10 || memcmp(h, "reflector-", 10) != 0) return -1;
    hi = 10;
    if (dec(h, hl, &hi, &o->id) < 0 || hi >= hl || h[hi] != '-') return -1;
    hi++;
    if (dec(h, hl, &hi, &o->tag) < 0) return -1;
    if (hl - hi != 10 || memcmp(h + hi, ".reflector", 10) != 0) return -1;
    i = st[5];
    if (dec(s, en[5], &i, &o->port) < 0 || i != en[5] || o->port > 65535UL) return -1;
    for (k = 6; k + 1 < nt; k++) {
        if (en[k] - st[k] == 3 && memcmp(s + st[k], "typ", 3) == 0) {
            relay = (en[k + 1] - st[k + 1] == 5 && memcmp(s + st[k + 1], "relay", 5) == 0);
            break;
        }
    }
    return relay ? 0 : -1;
}
