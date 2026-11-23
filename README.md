# telegram-call-engine-c

A small, portable **C89 engine for Telegram voice (and experimental video) calls**: the
media-plane protocol of Telegram's call library "2.7.7" (the `tgcalls` generation) plus the
older libtgvoip "2.4.4" protocol, written for a 2008 phone (Nokia N79, 330 MHz ARM11, 64 KB
thread stacks, no writable static data, GCC 3.4.3) and therefore usable almost anywhere.

It is the call core of [RetroTele](https://github.com/manojanasuri16/RetroTele), a Telegram
client for Nokia S60 3rd Edition phones. On the N79 it carried real voice calls with the
official Telegram apps. Everything here is plain C with **no sockets, no clock, no threads, no
malloc and no floating point**: you feed it datagrams and a millisecond clock, and drain an
output queue. Porting to another platform means writing ~100 lines of socket glue.

> Not affiliated with or endorsed by Telegram. You need your own `api_id`/`api_hash`, and the
> Telegram API terms apply to anything you build on top. The MTProto side (phone.requestCall,
> DH key exchange for the call key) is *not* part of this repo: see
> [mtproto-py22](https://github.com/manojanasuri16/mtproto-py22) for a client that can do it.

## Status (honest version)

| Part | Verified how |
|---|---|
| Host unit and simulation tests (below) | PC, gcc, ASan + UBSan: all pass (see "Tests") |
| 2.7.7 voice: ICE over Telegram's reflector, encrypted transport, RTP/Opus | **real calls on a Nokia N79** with the official Android/iOS apps (RetroTele 0.12.0, 2026-11-22) |
| legacy 2.4.4 voice | real calls on an N79, but only against clients that still ship libtgvoip 2.4.4 (e.g. a modded Telegram); the current official apps no longer do |
| 2.7.7 video (H.264 RTP packetizer, depacketizer with reorder buffer + NACK, RTCP SR/RR/PLI/REMB, VideoFormats/VideoParameters signalling) | implemented and unit/simulation tested on the PC; used on the N79 in RetroTele 0.14.x with a hardware decoder and a software encoder, but only lightly tested, quality is modest (QCIF/QVGA, a few fps to ~15 fps) |
| Group calls, TURN/TCP, IPv6, WebRTC data channels | not implemented |

Only the N79 (Symbian S60 3rd Edition FP2, GCCE) was ever used on a real device. The code
is plain C89 and builds with gcc/clang on Linux; other targets are untested.

A native **H.264 software decoder** port for devices without a hardware decoder is in progress
and will be published separately later (it is not part of this repo).

## What is in it

```
src/
  c277_crypto.*   AES-256-CTR, SHA-1, HMAC-SHA1, CRC-32 and the MTProto-2-style KDF / msg_key (c277_seal / c277_open)
  c277_msg.*      EncryptedConnection message codec, candidate lists, RemoteMediaState, SDP "candidate:" lines
  c277_conn.*     reliable/unreliable EncryptedConnection channel (seq numbers, acks, resends): one for signalling, one for transport
  c277_refl.*     ReflectorPort framing (Telegram's custom UDP relay, not TURN), tag ranking
  c277_stun.*     STUN codec (binding request/response, integrity, fingerprint), tested with RFC 5769 vectors
  c277_ice.*      minimal ICE agent for one path through the reflector
  c277_rtp.*      RTP (Opus, 48 kHz clock) packetizer/parser and a jitter buffer with loss reports for PLC
  c277_video.*    H.264 RFC 6184 packetizer (single NAL / STAP-A / FU-A), depacketizer with reorder buffer + NACK, SPS parser, RTCP SR/RR/PLI/FIR/NACK/REMB
  c277_session.*  orchestrator: ties everything into one call object with a timer-driven API
  callproto.*     legacy libtgvoip 2.4.4 framing, INIT handshake, acks (+ callproto_crypto.*: AES-IGE, SHA-256, shared with c277_crypto)
tests/            C tests (unit, lossy two-party simulations, RFC 5769 vectors), cross-checked against Python (tools/crosscheck.py)
legacy/           tests for the 2.4.4 code
docs/             protocol documentation (see below)
run_tests.sh      builds and runs everything with ASan + UBSan
```

About 4,400 lines of C including headers. A `c277_session` is about 60 KB: allocate it on
the heap, not on a small stack.

## Documentation

These are the working notes written while implementing the protocol from the open-source
clients' behaviour. They are detailed and mostly accurate, but are research notes, not a
specification: the video spec's header still says "nothing here is implemented" (section 7 and
the code are newer), and some paths refer to the RetroTele repo layout.

- [docs/CALL-PROTOCOL.md](docs/CALL-PROTOCOL.md): the legacy 2.4.4 protocol (signalling objects, relay framing, handshake, Opus 60 ms frames).
- [docs/CALL-VERSIONS.md](docs/CALL-VERSIONS.md): which library versions the Telegram server and official apps accept, and why old versions get `CALL_PROTOCOL_COMPAT_LAYER_INVALID`. Key facts: the server accepted 2.7.7 only with `udp_p2p=1`; relay candidates use component 0 and no `raddr`.
- [docs/CALL-277-SPEC.md](docs/CALL-277-SPEC.md): the 2.7.7 design: reflector, ICE, EncryptedConnection, RTP, crypto, work packages and N79 fit.
- [docs/CALL-VIDEO-SPEC.md](docs/CALL-VIDEO-SPEC.md): video negotiation, RTP H.264, RTCP, and (section 7) what was implemented for the N79.

## How a call fits together

```
 your MTProto client                    this engine                          your platform glue
 ---------------------   key, phoneConnection list   ----------------   UDP datagrams, clock
 phone.requestCall /  -->  c277_session_init()   -->  c277_session  <-->  sockets, audio, codec
 acceptCall (DH)           on_signaling()/on_udp()     tick() / out queue
 updatePhoneCall...   <--  C277_OUT_SIGNAL blobs
                           (phone.sendSignalingData)
```

1. Do the call set-up through the Telegram API yourself (DH exchange gives a 256-byte key; the
   server returns `phoneConnection` entries with a reflector id, ip, port and 16-byte peer tag;
   announce `library_versions: ["2.7.7"]` and `udp_p2p = 1`).
2. `c277_session_init(s, key256, is_outgoing, conns, nconns, random_bytes, nrnd)`.
3. Loop: feed received UDP datagrams with `c277_session_on_udp`, signalling blobs from
   `updatePhoneCallSignalingData` with `c277_session_on_signaling`, call `c277_session_tick`
   at least every 20 ms, then drain `s->out`: items of kind `C277_OUT_UDP` are sent to
   `ip:port`, `C277_OUT_SIGNAL` go out through `phone.sendSignalingData`. Set `s->out.n = 0`
   afterwards.
4. Audio: `c277_session_send_opus()` with one Opus packet (any valid TOC; N79 used 8 kHz mono,
   20-60 ms) and `c277_session_poll_opus()` for received packets (`C277_JB_PACKET`,
   `C277_JB_LOST` = run packet-loss concealment, `C277_JB_EMPTY`).
5. Video (optional): `c277_session_video_enable`, `c277_session_video_put` / `_pump` for
   sending Annex-B access units, `c277_session_rx_enable` + `c277_session_vrx_take` for
   receiving, `c277_session_take_idr_req` to know when to force a keyframe.

Minimal skeleton (untested pseudo-glue, API names are real, see `src/c277_session.h`):

```c
#include "c277_session.h"

static c277_session *s;          /* malloc(sizeof *s): ~60 KB */

void call_start(const u8 key[256], int outgoing, const c277_sess_conn *c, u32 nc, const u8 rnd[56])
{
    s = (c277_session *)malloc(sizeof *s);
    if (c277_session_init(s, key, outgoing, c, nc, rnd, 56) != C277_SESS_OK) { /* no usable connection */ }
}

void on_timer_20ms(u32 now_ms)
{
    int i;
    c277_session_tick(s, now_ms);
    for (i = 0; i < s->out.n; i++) {
        c277_out_item *o = &s->out.item[i];
        if (o->kind == C277_OUT_UDP)    udp_send(o->ip, o->port, o->data, o->len);
        else                            send_signaling_data(o->data, o->len);
    }
    s->out.n = 0;
}
```

The capture/logging helpers (`c277_session_capture`) never log keys or peer addresses.

## Build and tests

Needs `gcc` and `python3` (3.x) on a Unix host.

```sh
sh run_tests.sh          # 2.7.7 stack: Python cross-check + 3 C test programs with ASan/UBSan
sh legacy/run_tests.sh   # legacy 2.4.4 code
```

Last run (2026-11-23, Linux, gcc): `test_call277` 491 checks, `test_session` 1,263 checks and
`test_video` 193 checks, 0 failures, including lossy/duplicating/jittery two-party simulations
(voice and video); legacy: 6,594 checks, 0 failures. One test (`test_capture`) replays a
real capture of an official client when `fixtures/official_caller_capture.txt` exists; real
captures contain keys and addresses and are **not** published, so it prints `skipped: no
capture`. A handful of byte strings in `tests/test_video.c` are the first RTP/RTCP bytes of
an official client's video stream (SPS/PPS, an RTCP sender report): protocol constants only.

To use the code on Symbian S60 3rd Edition, build with the GnuPoc/GCCE toolchain from
[symbian-s60v3-toolchain](https://github.com/manojanasuri16/symbian-s60v3-toolchain): add the
`src/*.c` files to an `.mmp` (`c277_crypto.c` already `#include`s `callproto_crypto.c`: do not
list that file twice). RetroTele does this in its `tgcallaudio.exe` helper (see
[symbian-s60v3-media-notes](https://github.com/manojanasuri16/symbian-s60v3-media-notes) for
its audio side and [opus-symbian-s60](https://github.com/manojanasuri16/opus-symbian-s60) for
the codec). The Symbian build was **not** redone from this repository layout.

## Design rules that keep it portable

C89 only; fixed arrays, caller-owned structs; no `static` writable data (Symbian DLLs have
none); big structs on the heap; time is an argument (wrap-safe `u32` ms); endian-neutral
byte access; no floating point.

## Known limitations

- IPv4/UDP only, one reflector path per call, no TCP or TURN fallback, no ICE for host candidates beyond what the reflector path needs.
- Needs the Telegram server to accept `2.7.7` (verified in Nov 2026); Telegram may change this at any time.
- Video: send path expects Annex-B units from your encoder (baseline, `42e01f`, packetization mode 1); receive depacketizes to access units for your decoder. Only one H.264 format is offered.
- The docs describe the behaviour of the official clients as observed/read in 2026; they will go stale.

## Credits and licence

MIT, see [LICENSE](LICENSE). The protocol knowledge comes from reading the public
`libtgvoip` and `tgcalls` sources (not copied: this is an independent implementation) and
from RFC 5389, RFC 5245, RFC 5769, RFC 6184, RFC 3550/4585 and the WebRTC documents. AES and
SHA code is small-footprint table-based C written for this project (shared with the mtproto-py22 native module); it is not hardened against side channels, so do not use it as a general crypto library.
