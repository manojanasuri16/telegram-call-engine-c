# Telegram call library "2.7.7" (tgcalls InstanceImpl, ProtocolVersion V0): relay-only voice client feasibility spec

Researched 2026-11-22. Companion to CALL-PROTOCOL.md (legacy 2.4.4) and CALL-VERSIONS.md.

## 0. Sources and pinning (read this first)

- AUTHORITATIVE: TelegramMessenger/tgcalls commit **545f5ae599f8282e1ae3f38aaff166d179d75703** (2026-10-27, the pin DrKLO/Telegram master uses; also the one named in CALL-VERSIONS.md). All "pin:" line numbers below refer to it (raw.githubusercontent.com/TelegramMessenger/tgcalls/545f5ae.../tgcalls/<file>).
- TRAP: the GitHub default branch `master` of tgcalls is STALE (d20de8e, 2022-02-28). Its NetworkManager.cpp uses stock `cricket::TurnPort` for the reflectors. The pinned commit uses `ReflectorRelayPortFactory` -> custom `v2/ReflectorPort.cpp` (NetworkManager.cpp pin:119, :176-184). Everything in this spec is the pinned behaviour. Peers on builds older than ~2024 (stock TURN against "reflector"/hex(peer_tag) creds) are NOT interoperable with the ReflectorPort scheme (candidate formats differ); history shows ReflectorPort in the 2.7.7 path somewhere between 2022-10 and 2025-01 (exact commit not identified).
- Also read: tdesktop dev `Telegram/SourceFiles/calls/calls_call.cpp` (AppendServer :90-190, instance creation :1100-1260, sendSignalingData :766, handleSignalingData :1003), DrKLO `VoIPService.java:3575-3640`, `Instance.java:206-243`, `org_telegram_messenger_voip_Instance.cpp:829-990`, tgcalls `tools/cli/main.cpp` and `CLAUDE.md` (pin), libwebrtc m125 `p2p/base/{port,connection,p2p_transport_channel}.cc` (webrtc-sdk mirror; Telegram's fork may differ slightly).
- Meta::Create forces V0 for "2.7.7" and V1 for "5.0.0" (Instance.cpp pin:42-46). V0 = no RemoteNetworkStatus messages (Manager.cpp pin:401,426), video extensions limited. InstanceImpl::GetVersions = {"2.7.7","5.0.0"} (InstanceImpl.cpp pin:190-195), GetConnectionMaxLayer = 92. tdesktop registers InstanceImpl (calls_call.cpp:73); Android registers it (CALL-VERSIONS.md).

Key corrections to CALL-VERSIONS.md section 3: (a) reflectors are NOT TURN in the current engine, they use the small custom ReflectorPort UDP framing (section 2); no TURN allocate/MD5/long-term credentials needed. (b) EncryptedConnection crypto is AES-256-CTR (not IGE) with SHA-256 KDF. (c) ICE parameters travel through the signalling channel only (phone.sendSignalingData), there is no "InitialSetup" message and no DTLS/SRTP in 2.7.7.

## 1. End-to-end flow (after phoneCall with key arrives)

Inputs from signalling (same as legacy, CALL-PROTOCOL.md sec.1): 256-byte raw DH key `K`; `isOutgoing` (we are caller); `connections`. New for 2.7.7: use `phoneConnection{id,ip,port,peer_tag[16],tcp}` entries (skip tcp=true for use, but KEEP them in the id ranking, see 2.1). `phoneConnectionWebrtc` (real TURN/STUN) is ignored in the minimal client.

Protocol advert (requestCall/acceptCall/confirmCall): `phoneCallProtocol#fc878fc8 flags udp_p2p=0 udp_reflector=1 min_layer=65 max_layer=92 library_versions=["2.7.7"]`. udp_p2p=0 makes `p2p_allowed` false so the peer's `enableP2P=false` (NetworkManager.cpp pin:128-137: disables UDP/STUN/reflexive, relay only). Server picks library_versions[0] of the intersection (not verifiable here).

Signalling transport: `phone.sendSignalingData#ff7a9383 peer:InputPhoneCall data:bytes = Bool` out; `updatePhoneCallSignalingData#2661bf09 phone_call_id:long data:bytes` in (api.tl; tdesktop calls_call.cpp:766,1003). `data` = one EncryptedConnection(Signaling) packet verbatim (Manager.cpp pin:111-117, 255-262). No other wrapping. The first signalling packets of the peer can arrive before our key is ready: queue them (peer resends after 3 s anyway).

Timeline (each side symmetric; Manager.cpp pin:146-250, NetworkManager.cpp pin:109-216):
1. Build two EncryptedConnections over K: SIGNALING (x+128) and TRANSPORT.
2. For every reflector: open UDP socket to ip:port, send HELLO every 500 ms until any valid datagram returns (sec 2.2), then every 10 s. When a reflector is READY, create the local relay candidate `reflector-<id>-<randomTag>.reflector:<port>`.
3. Per gathered candidate, send **signalling** `CandidatesListMessage{[cand], ufrag, pwd}` (msg id 1, requires ack) (NetworkManager.cpp pin:309-312). Official peers send ONE candidate per message, repeated per reflector. Also at MediaManager::start the peer sends `VideoFormatsMessage` (id 2) over signalling (MediaManager.cpp pin:465): we must ack/skip it, and we simply never send ours (then no video is ever negotiated; audio-only).
4. On receiving the peer's Candidates: store peer ufrag/pwd (first message wins, NetworkManager.cpp pin:221-232), keep candidates of form `reflector-<id>-<tag>.reflector` whose `<id>` equals one of our ports' id and port equals our port; drop everything else (host/srflx/other ids).
5. ICE over the reflector (sec 2.3): both sides send STUN binding checks through the reflector; controlling = caller (NetworkManager.cpp pin:199).
6. When a check succeeds (we got a valid response), the path is "connected". Peer's MediaManager then enables audio sending (MediaManager::setIsConnected pin:~545-575) and sends over TRANSPORT: `VideoParametersMessage`(8) and `RemoteMediaStateMessage`(4) (both ack-required) (MediaManager.cpp pin:572,766). We send RemoteMediaState{audio=Active=1,video=0} (state byte 0x01) over TRANSPORT then RTP audio.
7. Media: `AudioDataMessage`(5) carrying one plain RTP packet each way (sec 4). No SRTP, no DTLS.
8. Liveness: peer declares Failed if no packet arrives for 20 s (NetworkManager.cpp pin:287-300). Keep STUN pings/audio flowing. Hang up via phone.discardCall (no in-band bye).

## 2. Reflector transport (replaces TURN) - exact bytes

### 2.1 Identities
- `tag16` = phoneConnection.peer_tag (16 bytes). Android/tdesktop pass username="reflector", password=hex(tag16); ReflectorPort parses it back (ReflectorPort.cpp pin:162-171). `tag12` = tag16[0..12).
- `randomTag` = our random nonzero uint32 per port (pin:155-160); on the wire it is the raw native-endian bytes (`(uint8_t*)&randomTag_`) => **little-endian** for every shipping client (ARM/x86).
- `ownTag16 = tag12 || LE32(randomTag)`.
- `id` (1 byte, serverId) = 1-based rank of the connection's `id:long` in the ascending (signed) sorted list of ALL `phoneConnection` ids of the call (including tcp ones, excluding webrtc ones): VoIPService.java:3590-3606, calls_call.cpp:77-88,134. Both sides compute the same mapping; it is embedded in candidate hostnames and checked on receive (ReflectorPort.cpp:536-543, 781). A mismatch = silently no pairing.
- Peer tags differ per role in the official CLI (byte0 0x00 caller / 0x01 callee, tools/cli/main.cpp:464-474, rest equal); the reflector routes and rewrites the 16-byte header to the receiver's tag. We always use the tag16 given to us.

### 2.2 Datagrams (UDP to reflector ip:port; IPv4 only)
HELLO, 40 bytes (ReflectorPort.cpp pin:317-355):
```
ownTag16[16] | FF*12 | FE FF FF FF | 00 00 00 00 00 00 00 7B   (u64 BE = 123)
```
Sent immediately after socket creation (state CONNECTED) every 500 ms until READY, then every 10 s (pin:357-370).
READY: any datagram of >=16 bytes from exactly the server ip:port whose first 12 bytes == tag12 (pin:706-753; only 12 bytes compared; reply content not needed). Datagrams >=28 bytes whose bytes 16..28 are all FF are control replies (CALL-PROTOCOL.md 2.4 SELF_INFO layout), ignored for data (pin:755-768).

DATA out (pin:611-675): `tag12 | LE32(peerRandomTag) | LE32(ownRandomTag) | BE32(len) | payload | 00 pad to multiple of 4`.
DATA in (pin:755-791): `tag12 | LE32(ownRandomTag) | LE32(senderRandomTag) | BE32(len) | payload...`; accept iff `len <= size-24`. `senderRandomTag` identifies the remote candidate (`reflector-<id>-<senderTag decimal>.reflector`).
Reflector-side behaviour (registration by HELLO, routing by tag12 + destination randomTag, header rewrite) is inferred from the client code and the tgcalls commit message of 2026-10-27 ("stand-in reflector routes by tag and rewrites the tag to the receiver's"); not observed on a real server by me.

Public reflector list: https://core.telegram.org/getReflectorList (ip:port 596-599, many in 91.108.13.x). tgcalls CLAUDE.md states the CLI routes through real reflectors with RANDOM tags (no Telegram account): usable as an offline test bed.

### 2.3 ICE-over-reflector (what a relay-only client must implement)
Candidate = ICE connection pair of (our reflector port) x (peer reflector candidate with same id). Single path => no candidate sorting, no pruning, no gathering of host/srflx.

**Candidate SDP line** (sent in CandidatesList; peer parses with webrtc `JsepIceCandidate::Initialize`, Message.cpp pin:69-92):
`candidate:<foundation> 1 udp <priority> reflector-<id>-<randomTag>.reflector <port> typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag <ourUfrag> network-id 1 network-cost 10`
Foundation any digits; priority e.g. `(2<<24)|(0xFFFF<<8)|255` = 33554431+... (value only affects pair order; single pair). raddr/rport kept for parser safety (unverified whether required). Parse peer lines tolerantly: token 5 hostname, token 6 port, `typ relay`. Component must be 1, protocol udp.

**ICE credentials**: ufrag 4 chars, pwd 24 chars (ICE_UFRAG_LENGTH/PWD_LENGTH; NetworkManager.cpp pin:91). Peer requires ufrag>=4, pwd>=22 chars.

**Critical dynamic (the "prflx twin")**: with `resolveRemoteCandidateIp` hard-off in 2.7.7 (tgcalls commit 2026-10-27 message), the peer's connection built from our signalled candidate is keyed by hostname, while every inbound reflector packet carries the server's resolved IP. Responses to the peer's own pings therefore never match that connection. The path comes up only on a peer-reflexive twin which the peer's Port creates when it receives OUR binding request from an unknown (resolved) address (p2p_transport_channel.cc OnUnknownAddress: needs STUN PRIORITY and our ufrag known from our CandidatesList). **=> We MUST originate binding requests ourselves, in both roles. An "ICE-lite" responder-only client will not come up.** Also we must answer the peer's requests (they are what the peer's controlled/controlling logic and keepalive use).

**STUN codec** (RFC 5389 + webrtc specifics, port.cc :430-480, connection.cc :505-545,700-770,1010-1095):
- Header: type u16 BE (0x0001 req, 0x0101 success, 0x0111 error), len u16, cookie 0x2112A442, txid[12]. Attributes TLV, 4-byte padded.
- **FINGERPRINT is mandatory** for every STUN packet the peer accepts (port.cc:430-440 "all STUN packets will have a valid fingerprint"): attr 0x8028, value = CRC32(msg bytes before the attribute, with header length field already counting the 8 bytes of FP) XOR 0x5354554E.
- Request we send: USERNAME(0x0006) = `<peerUfrag>:<ourUfrag>`; PRIORITY(0x0024) u32 (any, required, else 400); ICE-CONTROLLING(0x802A) u64 tiebreak (caller) or ICE-CONTROLLED(0x8029) (callee); USE-CANDIDATE(0x0025, empty) only when controlling and after the first success (regular nomination; peer's controlled side nominates on any request carrying it, connection.cc:645-665); MESSAGE-INTEGRITY(0x0008) = HMAC-SHA1 key = **peer pwd** (raw ASCII), computed with header length = bytes up to and including MI (+24), over bytes before MI; then FINGERPRINT.
- Response we send to a peer request (connection.cc:717-758): success 0x0101 with same txid; XOR-MAPPED-ADDRESS(0x0020: 00 01 | port^0x2112 | ip^0x2112A442) = reflector ip:port; MESSAGE-INTEGRITY with key = **our pwd**; FINGERPRINT. Before answering: check USERNAME starts with `<ourUfrag>:` and verify MI with our pwd (port.cc:458-482); else ignore (or 401).
- Incoming responses: peer-side (and ours) require valid MI keyed with the responder's pwd (connection.cc:527-535). Verify with peer pwd; ignore otherwise. Ignore all unknown attributes (GOOG-NETWORK-INFO 0xC057, RETRANSMIT_COUNT, NOMINATION 0xC001, SOFTWARE 0x8022 "Telegram ", etc).
- STUN vs data demux on the unwrapped payload: STUN iff len>=20, `(b[0]&0xC0)==0`, `b[4..8]==21 12 A4 42`. Else it is an EncryptedConnection packet (random-looking, false positive 2^-32).
- Cadence (my choice, webrtc is similar): ping every 500 ms until first valid response; then every 2 s; on role conflict ignore (roles are fixed by call direction; both sides in conflict is impossible barring bugs). Respond to every request immediately.
- Roles: caller = CONTROLLING. Tie-breaker random u64.

TURN features NOT needed: Allocate/Refresh/CreatePermission/ChannelBind, MD5 long-term key, realm/nonce, Data/Send indications. No STUN server. No candidate gathering of host/srflx. No TCP/IPv6.

## 3. EncryptedConnection, byte for byte (EncryptedConnection.cpp pin; CryptoHelper.cpp)

Two instances over the same 256-byte K: `SIGNALING` and `TRANSPORT`; they differ only by x (+128) and limits.

**Wire packet**: `msgKey[16] | ciphertext[N]`, N>=5 (min packet 21 bytes, pin:~455).
**Plaintext**: `seq u32 BE | type u8 | body ...` then optionally further entries `seq u32 BE | type u8 | body` and ack entries `ackedSeq u32 BE | FF`.

**Keys** (pin:124,172,412-420; CryptoHelper.cpp:8-59):
```
x_send = (isOutgoing ? 0 : 8) + (SIGNALING ? 128 : 0)
x_recv = (isOutgoing ? 8 : 0) + (SIGNALING ? 128 : 0)      // i.e. the peer's x_send
msgKeyLarge = SHA256( K[88+x .. 88+x+32) || plaintext )
msgKey      = msgKeyLarge[8..24)                            // 16 bytes
a = SHA256( msgKey[16] || K[x .. x+36) )
b = SHA256( K[40+x .. 40+x+36) || msgKey[16] )
aesKey[32] = a[0..8) || b[8..24) || a[24..32)
aesIv [16] = b[0..4) || a[8..16) || b[24..28)
ciphertext = AES-256-CTR(aesKey, iv=aesIv as 128-bit big-endian counter, no nonce split, counter starts at iv, +1 per 16-byte block), length = len(plaintext), no padding
```
Receive: derive key/iv from the received msgKey, decrypt, recompute msgKey over plaintext, constant-time compare, then replay check. AES encrypt only (CTR). Existing helper's AES-256 block + SHA-256 suffice; IGE not used.

**seq word**: bit31 = SINGLE_MESSAGE_PACKET, bit30 = REQUIRES_ACK, bits0-29 = counter (pin:11-15). `counter` increments for EVERY new message or standalone ack/empty packet (`++_counter`, computeNextSeq pin:303-316); the first entry's seq doubles as the packet seq (replay window 64 over that counter, registerIncomingCounter pin:431-453: reject if seen or `counter+64 <= largest`).

**Message ids and bodies** (Message.h pin; Message.cpp pin:94-345): all ints BE. `str = u32 len | bytes` (len < 65536).
| id | name | ack | body |
|---|---|---|---|
| 1 | CandidatesList | yes | u8 n; n*str(SDP candidate); str ufrag; str pwd |
| 2 | VideoFormats | yes | u8 n; n*(str name; u8 np; np*(str key; str value)); u8 encodersCount |
| 3 | RequestVideo | yes | empty |
| 4 | RemoteMediaState | yes | u8 state = (video<<1)\|audio; audio:0=Muted,1=Active (Instance.h pin:152-155); video 0..2 |
| 5 | AudioData | no | if not single-packet: u16 len + data; if single-packet: data = rest of packet |
| 6 | VideoData | no | same as 5 |
| 7 | UnstructuredData | yes | same framing as 5 |
| 8 | VideoParameters | yes | u32 aspect*1000 |
| 9 | RemoteBatteryLevelIsLow | yes | u8 |
| 10 | RemoteNetworkStatus | yes | u8 lowCost; u8 lowData (optional) - V1 only, tolerate |
| 0xFE | Empty | - | none; must be FIRST entry (carries acks/resends) |
| 0xFF | Ack | - | no body; entry is `ackedSeq u32 BE (full word incl. bit30!) | FF`; never first |
| 127 | custom raw | - | pump-host seam only, ignore |
A parser must be able to skip every type to find the next entry (VideoFormats is the only complex one; parse it fully or fail the packet). Unknown type => abort the packet (pin:599-601).

**Single-message packet** (pin:286): only when the packet holds exactly one non-ack-required message and no queued acks/resends; then seq has bit31 and no entry/length follows. All audio during steady state looks like: `seq(bit31) | 05 | RTP...`. If acks or unacked messages are pending the sender instead appends them as extra entries after the audio message (so audio then has `u16 len`).

**Reliable messages** (pin:278-330,332-400): ack-required message gets seq|bit30, is stored (full serialized bytes with its original seq) in `notYetAcked`, sent once; it is re-appended to subsequent outgoing packets when `lastSent + minDelay <= now` (minDelay 300 ms transport / 3000 ms signalling, pin:786-800) in order, stopping at the first not-due or non-fitting item; a dedicated Empty packet carrying them is scheduled after maxDelayBeforeMessageResend 1000 ms / 5000 ms signalling. Entry is removed when an Ack entry with that exact seq word arrives (pin:~770). Limit packet size 1452 (transport) / 16384 (signalling).
**Receiving reliable messages** (pin:526-640): for each ack-required entry: always queue an Ack (even for duplicates), deliver only if not yet seen (dedupe by counter list; registerSentAck pin:744). If any NEW ack-required arrived => send acks immediately (an Empty packet: `seq(++counter, no flag bits) | FE | (ackedSeq|FF)*`), else within 1000 ms (transport) / 5000 ms (signalling). Empty must be the first entry; Ack must not be first; single-bit packets must contain exactly one entry.
Minimal sender may skip packing: send each reliable message in its own packet and re-send whole packet on timer until acked.

## 4. Media

- Audio travels as **plain RTP (RFC 3550, no SRTP, no header encryption)** inside AudioDataMessage; RTCP also goes via id 5 (MediaManager.cpp pin:998-1013 `IsRtcpPacket` branch). All protection is EncryptedConnection.
- Payload type **111**, `opus/48000/2` (pin:375-390). SSRCs fixed: caller sends **2**, receives 1; callee sends **1**, receives 2 (pin:36-38,279-282). FEC SSRCs unused for audio.
- RTP header: V=2, P=0, X=0 (transport-cc extension id 1 is registered on the peer but optional; omitting it is legal), CC=0, M=0, PT=111, seq u16 (random start, +1), timestamp u32 on a **48 kHz clock regardless of our 8 kHz coding** (+2880 per 60 ms), SSRC. 12-byte header then the raw Opus packet (RFC 7587), mono. Peer SDP says 2 channels but without `stereo=1` it encodes/decodes mono.
- Opus: encoder advertised bitrate range 6..32 kbps (start 8), `useinbandfec=1`, **ptime 120** (pin:380-390) i.e. peer packets may be 120 ms (also 20/40/60); WebRTC Opus decoder accepts any valid TOC, so we may send 8 kHz NB mono at 20/40/**60 ms** (recommend 60 ms: 17 pps, same as legacy framing; 2.4.4 doc already uses 60 ms) with INBAND_FEC on. Field trial `WebRTC-Audio-Allocation/min:32kbps,max:32kbps` pins the peer's send bitrate near 32 kbps: expect WB/SWB hybrid/SILK packets from official peers, up to 120 ms each; our decoder must accept `opus_decode(frame_size=960 @8 kHz)` and mono output at Fs=8000.
- RTCP / feedback needed to keep playing: **none required**. Peer decodes from RTP alone (NetEq adaptive jitter buffer, no NACK for audio, no RTX). Missing transport-cc feedback means the peer's BWE sees no feedback (its audio rate is pinned, so audio continues) but its "signal bars" stat (collectStats pin ~600-620, derived from send_bandwidth_bps) may show low; cosmetic, unverified. RTCP SR/RR from the peer: ignore. Optional later: RTCP RR + transport-cc feedback.
- Jitter: peer NetEq adapts to our 60 ms cadence; keep timestamp/seq contiguous, no DTX (WebRTC default), no marker handling needed. Our receive side needs our own jitter buffer for 20..120 ms frames (reuse legacy one, extend to 120 ms frames, target 120-200 ms).
- Mute: RemoteMediaState audio=Muted; simply stop sending RTP.

## 5. Signalling messages to understand/produce (summary)
Must produce: CandidatesList (1) via signalling; RemoteMediaState (4) via transport; Ack/Empty. Optional: none. Must parse and ack/skip: VideoFormats (2) [signalling], VideoParameters (8), RemoteMediaState (4), Battery (9), NetworkStatus (10), RequestVideo (3), VideoData (6, ignore). There is no InitialSetup, no fingerprints, no SDP. All of the above on signalling use the SIGNALING key; media and media-state use TRANSPORT through the reflector.

## 6. Minimal implementation plan (C, GCC 3.4.3 C/C++03, active objects, no threads)

| WP | Content | C lines | Risk |
|---|---|---|---|
| 1 | Crypto glue: AES-256-CTR from existing AES block, PrepareAesKeyIv, msgKey, seal/open | ~200 | low (testable offline) |
| 2 | EncryptedConnection state machine x2: counters, replay window, ack/dedupe, resend queue, multi-entry build/parse, timers | ~450 | medium |
| 3 | Message codec (ids 1,2-skip,3-10, 0xFE/0xFF) + SDP candidate build/parse | ~280 | low-medium |
| 4 | ReflectorPort client: hello/keepalive, READY, tag12/randomTag, frame in/out, multi-reflector ids | ~220 | medium (server behaviour inferred) |
| 5 | STUN codec: HMAC-SHA1 (from existing SHA-1), CRC32, XOR-MAPPED, MI/FP build+verify | ~300 | medium |
| 6 | ICE agent: roles, 500 ms/2 s pings, response, nomination, writable/connected state, 20 s timeout | ~250 | **high** (prflx-twin dynamics; peer-side behaviour only observable against real peer) |
| 7 | RTP packetize/depacketize (48 kHz clock), jitter buffer for 20-120 ms Opus frames, 8 kHz decode of WB/SWB packets, RemoteMediaState | ~300 | medium (CPU) |
| 8 | Signalling glue (python/PyS60 side): sendSignalingData, update handler, version advert, reflector id ranking, key handoff to helper | ~150 py | low (RetroTele already does the rest) |
| 9 | Integration: call state machine, timers on the 20 ms AO tick, logging, hangup, regression of legacy path | ~300 | medium |
Total native C ~2,300-2,500 lines (+~150 python); 9 work packages. Smallest viable subset: everything above; nothing can be cut except: video/battery/network parsing details (skip-only), IPv6, TCP, multi-reflector (use 1-2 reflectors), transport-cc/RTCP.

Offline testing on a PC:
1. Vectors: port WP1-3,5 as host C or Python; cross-check crypto/framing by compiling pin `CryptoHelper.cpp` + `EncryptedConnection.cpp` + `Message.cpp` with stubs for the few rtc_base types (ByteBuffer, CopyOnWriteBuffer) and generating golden packets. Medium effort (~1 day).
2. Self-loop: two instances of our own stack (caller/callee, tag byte0 0/1) through a local ~80-line Python stand-in reflector (HELLO registration, route by tag12 + dest randomTag, rewrite header) - tests WP2-7 deterministically, with packet loss/dup injection.
3. Same through a REAL public reflector with random tags (tgcalls CLAUDE.md says the official CLI does exactly this with no account) - validates ReflectorPort framing and server behaviour. May be blocked by firewalls (the tgcalls dev network blocked UDP to reflectors).
4. Real interop: build tgcalls_cli per tgcalls CLAUDE.md (Bazel 9.2.0 in the Telegram-iOS tree, Linux supported but heavy), add `Register<tgcalls::InstanceImpl>()` (main.cpp registers only V2 variants) and replace the in-process SignalingBridge with a socket to a host build of our C stack; run `--mode reflector --version 2.7.7`. This is the only way to test ICE/prflx/audio against real libwebrtc without Telegram accounts. Effort: several days, build-environment risk; not attempted by me.
Needs real calls: server acceptance of library_versions ["2.7.7"], what `connections` contain (phoneConnection vs only phoneConnectionWebrtc), real reflector routing, Android/iOS/Desktop audible interop, N79 CPU/jitter, battery.

## 7. N79 fit and blockers

- CPU: per packet crypto = 3 SHA-256 invocations (~150-byte inputs, 2 x 2 blocks + msgKey) + CTR: well under 1 MHz-equivalent at 17-50 pps. STUN HMAC-SHA1 + CRC32: negligible at 0.5-2 pps. RTP: trivial. Dominant: Opus. Encode NB 60 ms exists already (legacy, unmeasured at complexity 0-2). Decode of official peers' 32 kbps WB/SWB (SILK/hybrid, possibly CELT) packets at Fs=8000 is NEW load (legacy peers sent NB); estimate 15-40 MHz of 369 MHz, UNMEASURED; decoder state ~30 KB. Risk: peer cannot be told to send NB (no config path; no bitrate feedback since no RTCP/BWE). Worst case: fall back to complexity/limited downsample; may need a CPU measurement spike first.
- RAM: packets <2 KB; resend queues <10 KB; jitter 16 KB/s of 8 kHz PCM x ~0.5 s; Opus enc+dec ~60-80 KB; code ~80-120 KB. Total well under the 2 MB budget.
- Blockers/gaps in helper: need HMAC-SHA1 wrapper (~30 lines), CRC32, AES-CTR mode (AES block exists), random 64-bit/32-bit, little-endian packers; NO MD5, TURN, DTLS, SCTP, threads or libc++. C++03 only (no auto/lambda): keep plain C.
- Network: UDP only, one socket per reflector; keep alive HELLO 10 s + STUN. N79 Wi-Fi/3G NAT: reflector sees our public ip:port from HELLO (no STUN servers needed).
- Control: both roles needed (caller controlling+nominating, callee controlled). Tie-breaker only for ICE-CONTROLLING/CONTROLLED attrs; role conflict (487) can be ignored.

## 8. Verdict

**Feasible but very large** (comparable to ~2.5x the legacy 2.4.4 engine). It is not "not realistic": the WebRTC machinery collapses to (1) an AES-CTR/SHA-256 packet protocol, (2) a 40-byte-hello UDP relay protocol with single-path ICE checks (STUN with HMAC-SHA1+CRC32), (3) bare RTP+Opus. No TURN, DTLS, SRTP, RTCP, SDP or video needed.

Minimal viable scope: audio-only 1:1, IPv4/UDP, 1-2 reflectors, mono Opus 8 kHz NB send at 60 ms, no RTCP/transport-cc, no video/data messages beyond skip-parsing, signalling-only candidate exchange, both roles.

Effort estimate: ~2,300-2,500 lines C + ~150 python, 9 work packages; roughly 3-5 weeks of focused work including a PC reference harness and N79 on-device tuning, with the ICE/prflx step and N79 Opus decode CPU as the two items that can still sink it.

NOT verified (could not or did not test):
- Actual reflector server behaviour (HELLO reply content, routing/rewrite, tag semantics) and that current servers still return `phoneConnection` entries (vs only `phoneConnectionWebrtc`) to a client that advertises only 2.7.7; server acceptance of ["2.7.7"] intersection.
- Which builds of the official apps in the field use ReflectorPort for 2.7.7 (pinned master does; pre-2024/25 builds use stock TURN and would not pair with us); iOS behaviour not examined.
- libwebrtc details come from the m125 mirror, not Telegram's fork: FINGERPRINT mandatory, MI-on-response, USE-CANDIDATE handling, prflx creation. Whether the controlled peer selects without USE-CANDIDATE (we send it anyway). Whether `raddr/rport` are mandatory in the candidate line.
- The Opus frame length actually used by official peers (ptime=120 requested; frame lengths 10/20/40/60/120 all must decode).
- Whether tgcalls_cli can be built/extended for InstanceImpl 2.7.7 in reasonable time; the 2.7.7 path was not executed at all by me.
- N79 CPU for peers' WB/SWB Opus decode; signal-bar/BWE cosmetics without transport-cc feedback; the exact point at which ReflectorPort replaced TurnPort in the 2.7.7 NetworkManager.
