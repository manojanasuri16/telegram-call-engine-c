# Telegram legacy voice-call media protocol (libtgvoip "2.4.4"), minimal-client spec

Sources (read in full for this doc):
- libtgvoip `public` branch (header says "2.5") and tag `2.4.4`. Diffs 2.4.4 vs public touch none of the wire code
  (header/crypto/KDF2/INIT unchanged; only OpusEncoder bandwidth hint differs). `PROTOCOL_VERSION 9`, `MIN_PROTOCOL_VERSION 3`
  in both (PrivateDefines.h:29-30). File:line below refer to `public` unless noted.
- tgcalls `tgcalls/legacy/InstanceImplLegacy.cpp` (GetVersions returns "2.4.4"; `GetConnectionMaxLayer` = libtgvoip's).
- Android client DrKLO/Telegram `VoIPService.java`, `Instance.java`.
- core.telegram.org/api/end-to-end/voice-calls (old, pre-v7 doc: confirms x=0 for A->B, x=8 for B->A, peer_tag prefix for reflectors).

All multi-byte integers on the media wire are LITTLE-ENDIAN (Buffers.cpp:84-89, 157-184).
Everything below assumes: UDP relay only, Opus audio only, "short format" (peer proto >= 8), MTProto2-style crypto (KDF2/SHA256).

## 1. Inputs from signalling

From the MTProto layer (phone.requestCall / acceptCall / confirmCall, DH exchange, not covered here):
- `auth_key` 256 bytes (the DH shared key g_ab, 256 bytes, leading-zero padded). Used raw, no further hashing, as `encryptionKey`.
- `isOutgoing` = true if WE are the caller (the one who sent phone.requestCall). Selects key halves (below).
- Derived locally, needed only for old-format packets (we do not need them): keyFingerprint = last 8 bytes of SHA1(key);
  callID = last 16 bytes of SHA256(key) (VoIPController.cpp:414-422). Fingerprint also goes in phone.confirmCall `key_fingerprint`
  (that is the signalling-level int64 = same last 8 bytes of SHA1(key), little-endian long).
- `connections`: list of phoneConnection {id:long, ip, ipv6, port, peer_tag:bytes[16]} (phoneConnection with flag tcp=false; skip phoneConnectionWebrtc and tcp ones).
  Each becomes an `Endpoint(id, port, ipv4, ipv6, UDP_RELAY, peer_tag)` (tgcalls InstanceImplLegacy.cpp: EndpointType::UdpRelay -> UDP_RELAY, endpoint.peerTag copied).
  Use ONLY the IPv4 address (N79 has no IPv6). `id` is only a local key. Relay selection is dynamic (see sec. 4): INIT goes to every
  relay; use whichever answers (lowest RTT, preferredRelay).
- Peer tag semantic: each relay has its OWN 16-byte peer_tag; both parties receive the same tag for the same relay and the relay
  uses it to pair the two sockets. Prefix every datagram to that relay with that relay's tag.
- Call config (tgcalls Instance config as Android sets): initTimeout ~30 s, recvTimeout ~20 s (Config defaults in
  VoIPController.h:209: 30.0 / 20.0). dataSaving: set none. enableAEC/NS/AGC irrelevant for the wire. enableCallUpgrade=false, video off.

### Protocol / version negotiation (signalling side)
- phoneCallProtocol{udp_p2p, udp_reflector=true, min_layer, max_layer, library_versions[]}.
  - `udp_reflector` must be true; set `udp_p2p=false`/ignore P2P (we never use it; the peer cannot be forced off P2P by us, but peer
    falls back to relay: libtgvoip only tries P2P when allowP2p set on both sides; a peer that tries P2P pings will just get no
    answer from us and keeps relay. Also relay `phoneCall.p2p_allowed` can be ignored).
  - `max_layer = 92` (Android `Instance.getConnectionMaxLayer()` returns 92, Instance.java; tgcalls V2 also returns 92). It MUST be >= 92
    so the peer uses short format & MTProto2 before any INIT is exchanged (VoIPController.cpp:1403 `peerVersion>=8 || (!peerVersion && connectionMaxLayer>=92)`).
    The controller's `connectionMaxLayer` is `min(own, peer)`-style value Telegram passes in SetRemoteEndpoints; we hard-code short+MTProto2.
  - `min_layer = 65` (Android CALL_MIN_LAYER; value not re-verified here, 65 is what clients use).
  - `library_versions = ["2.4.4"]` (single string). Android picks `privateCall.protocol.library_versions.get(0)` from the phoneCall the
    SERVER returns (VoIPService.java:3615/3630), so the server selects; with only "2.4.4" advertised the common set can only be {"2.4.4"}.
- In-band (INIT): we send PROTOCOL_VERSION=9, MIN_PROTOCOL_VERSION=3. Peer rejects only if `our_min > its PROTOCOL_VERSION(9)` or `our_version < 3` (VoIPController.cpp:2309). Claim 9/3.
  Claiming a lower in-band version (e.g. 8) is also accepted but changes behaviour (proto>=9 adds video recv-ts only); 9 is simplest because INIT_ACK parsing below is identical for >=5.

## 2. Packet framing (UDP datagram)

```
+------------------+------------------+----------------------------------+
| peer_tag  [16]   | msg_key  [16]    | AES-256-IGE ciphertext [N*16]    |
+------------------+------------------+----------------------------------+
```
(SendPacket, VoIPController.cpp:2931-2985; short format => NO 8-byte key fingerprint, NO 4-byte length.)
The fingerprint (8 B) + 4-byte inner length appear only in the legacy "long format" (peer ver < 8) -- not implemented.

### Encrypt (sender) -- VoIPController.cpp:2946-2972, KDF2 at 3230
```
x_send = isOutgoing ? 0 : 8                      // caller=0, callee=8  (doc: "x=0 for A->B, 8 for B->A")
inner  = u16le(len(P)) || P || padding           // P = plaintext packet (header+payload, sec. 2.1)
         padding: padLen = 16 - (len(inner_without_pad) % 16);  if padLen < 16: padLen += 16   // i.e. 16..31 random bytes; total % 16 == 0
msg_key_large = SHA256( key[88+x_send .. 88+x_send+32) || inner )     // whole inner incl. length field and padding
msg_key = msg_key_large[8 .. 24)                                       // middle 16 bytes
```
KDF2(msg_key, x) (the MTProto-2 KDF with 36-byte slices):
```
sA = SHA256( msg_key[16] || key[x .. x+36) )
sB = SHA256( key[40+x .. 40+x+36) || msg_key[16] )
aes_key[32] = sA[0..8) || sB[8..24) || sA[24..32)
aes_iv [32] = sB[0..8) || sA[8..24) || sB[24..32)
```
Call KDF2(msg_key, x_send). Encrypt inner with AES-256-IGE (OpenSSL `AES_ige_encrypt` semantics = MTProto IGE:
aes_iv[0..16) = IV for ciphertext chain y0, aes_iv[16..32) = IV for plaintext chain x0) with `aes_key`.
Datagram = peer_tag || msg_key || ciphertext.

### Decrypt (receiver) -- ProcessIncomingPacket, VoIPController.cpp:1857-2056
1. Datagram must come from a known relay ip:port; first 16 bytes must equal that relay's peer_tag else drop ("wrong peerTag", :1868).
2. Datagram length after the tag must be >= 40 (:1930).
3. `msg_key = next 16 bytes`; rest = ciphertext, length must be %16==0 and <=1500 (:1980-1989).
4. `x_recv = isOutgoing ? 8 : 0` (opposite of sender). KDF2(msg_key, x_recv) -> decrypt IGE.
5. Verify: SHA256( key[88+x_recv .. +32) || decrypted )[8..24) == msg_key (:1997-2007). (decrypted = all bytes incl. u16 length and padding.)
6. innerLen = u16le at decrypted[0]; must be <= decryptedLen; and `decryptedLen - innerLen >= 16` (:2010-2019) (counts the 2-byte field as padding side).
7. Plaintext packet P = decrypted[2 .. 2+innerLen).

Direction check: caller encrypts with x=0 and the callee decrypts with x=0 (callee `isOutgoing=false` => x_recv=0). Consistent.

### 2.1 Plaintext packet P (short format, peer ver >= 8): header 14 bytes + extras + payload
(WritePacketHeader :1391-1436; parse :2080-2090)
```
off size  field
0   1     type          (PKT_*)
1   4     ack_seq       lastRemoteSeq: highest seq received from peer (0 if none yet)
5   4     seq           this packet's seq (outgoing counter, starts at 1, +1 per packet, incl. pings/acks; wraps mod 2^32)
9   4     ack_mask      bit (31-i) set  <=> seq (ack_seq-(i+1)) was received, i=0..31
13  1     flags         XPFLAG_HAS_EXTRA=1, XPFLAG_HAS_RECV_TS=2 (RECV_TS only with video; never set by us)
[if flags&1]  1: extra_count; then extra_count x { u8 len; u8 type; (len-1) data bytes }   // len includes the type byte
[if flags&2]  u32 recv_ts  (video only; ignore: we never set it; if peer sets it we must skip 4 bytes: read it after extras)
...   payload (type specific)
```
Receiver derives payload length `packetInnerLen = innerLen - 14` (:2090) (this ignores extras; use remaining bytes).
Duplicate detection: drop if seq already in the last 128 received; drop if too old (`seqgt(pseq, lastRemoteSeq-128)` fails) (:2128-2142).
ACK bookkeeping: peer's ack_seq/ack_mask acknowledge OUR packets (:2162-2185). `seqgt(a,b) = (a>b && a-b<=2^31-1) || (a<b && b-a>2^31-1)` (PrivateDefines.h:~127).
Unrecognised extras are parsed but safe to ignore; but you MUST parse `extra_count`/lengths to find the payload start.

### 2.2 Packet types (PrivateDefines.h:9-24)
```
 1 INIT        2 INIT_ACK     3 STREAM_STATE (old, ver<6)   4 STREAM_DATA   5 UPDATE_STREAMS (unused)
 6 PING        7 PONG         8 STREAM_DATA_X2  9 STREAM_DATA_X3  10 LAN_ENDPOINT   11 NETWORK_CHANGED
12 SWITCH_PREF_RELAY  13 SWITCH_TO_P2P   14 NOP   17 STREAM_EC
```
A minimal client sends: INIT, INIT_ACK, STREAM_DATA, PING (optional), PONG, NOP. It receives and ignores everything else (but still acks via normal header).
Receivers of STREAM_DATA must accept types 4, 8, 9 (X2 = 2 sub-frames, X3 = 3) in principle; libtgvoip 2.4.4 senders only emit type 4 (HandleAudioInput :1211).

### 2.3 Payloads
**PKT_INIT (1)** (SendInit :1536-1600; with connectionMaxLayer>=74):
```
u32 proto_version = 9
u32 min_proto_version = 3
u32 flags   = 0   (bit0 data saving, bit1 group calls supported, bit2 video send, bit3 video recv)
u8  audio_codec_count = 1
u32 codec[0] = 'OPUS' = FOURCC('O','P','U','S') = 0x4F505553  (written LE: bytes 53 55 50 4F)    // PrivateDefines.h:44-45 (value computed as (a<<24)|(b<<16)|(c<<8)|d)
u8  video_decoder_count = 0   (then, per decoder u32 codec)
u8  max_video_resolution = 0
```
Total = 4+4+4+1+4+1+1 = 19 bytes. (Wire bytes for FOURCC: since WriteInt32 is LE, the 4 bytes are 0x53,0x55,0x50,0x4F = "SUPO".)
Peer parses: ver, minVer (fail if minVer>9 or ver<3), flags, count, count x u32, and the video-decoder list only if flags indicate video on both sides (:2343-2356). With flags=0 peer stops reading; extra bytes harmless.

**PKT_INIT_ACK (2)** (:2357-2372; parse :2410-2425):
```
u32 proto_version = 9
u32 min_proto_version = 3
u8  stream_count = 1
per stream:  u8 id=1; u8 type=1 (STREAM_TYPE_AUDIO); u32 codec='OPUS'; u16 frame_duration_ms = 60; u8 enabled=1
```
Total 4+4+1+(1+1+4+2+1)=18 bytes. IMPORTANT: receiver READS and DISCARDS frame_duration and hard-codes **60 ms** (`in.ReadInt16(); stm->frameDuration=60;` :2423-2425). The sender's own stream is also hard-coded 60 (constructor :250-253). So the peer's decoder is fixed to 60 ms frames regardless of what we claim.
Peer ver < 5 uses 1-byte codec; we require peer >= 5 (all current clients are 9).
Peer parse requires packetInnerLen>10 to read versions (we send 18).
If peer INIT_ACK has stream_count 0 the receiver aborts silently; stream id: we use id 1 for audio on send (HandleAudioInput always writes stream id 1 | flags (:1189); receiver looks the id up in `incomingStreams` from OUR INIT_ACK).

**PKT_PING (6)**: no payload (relay-pings: `len=0`, :3601). Peer answers PKT_PONG.
**PKT_PONG (7)**: payload u32 = seq of the ping being answered (:2606-2608). On receiver RTT = now - sendTime of lastPingSeq (only used for relay selection).
**PKT_NOP (14)**: no payload; sent purely to carry acks (:3874).
**EXTRA_TYPE_STREAM_FLAGS (extra type 1)**: `u8 id; u32 flags` (STREAM_FLAG_ENABLED=1, DTX=2, EXTRA_EC=4, PAUSED=8) (:1092-1108). Optional: send in the header extras once after INIT_ACK to say audio enabled; default is enabled from INIT_ACK so not required.
(Other extras: LAN endpoint 3, network changed 4, ipv6 endpoint 7 -- ignore.)

### 2.4 Relay-level (reflector) TL packets, not encrypted
Both start with peer_tag (16B), then 0xFF bytes. Detected on receive by `buf[16..24)==0xFF.. && buf[24..28)==0xFFFFFFFF` (:1871-1873).
- **UDP ping to reflector** (SendUdpPing :3326-3348), 44 bytes:
  `peer_tag[16] || i32(-1) || i32(-1) || i32(-1) || i32(-2) || i64 random_query_id`  (all little-endian; -1=FF FF FF FF, -2=FE FF FF FF).
  Sent to every UDP relay at t=0 and every 0.5 s until evaluated (`SendUdpPings`, Post(..,0.0,0.5), RunRecvThread :1672; evaluation after 4th and 10th ping, :3519-3524).
- **Reply** `UDP_REFLECTOR_SELF_INFO` (tlid 0xc01572c7): `peer_tag[16] || FF*12 || u32 tlid=0xc01572c7 || i32 date || i64 query_id || u8[16] my_ip(IPv4 in last 4 bytes, ::ffff-style) || i32 my_port` (:1876-1900, need >=32 bytes after tlid).
  Used for UDP availability (counts pongs) and RTT. Not required to establish media. We may send 1-2 as a reachability probe.
- `UDP_REFLECTOR_PEER_INFO` (0x27D9371C) / `REQUEST_PACKETS_INFO` / `LAST_PACKETS_INFO` (PrivateDefines.h:~95-98): P2P-only (peer public-endpoint request = peer_tag || 16 x 0xFF, SendPublicEndpointsRequest :3253). Not needed; ignore any such reply.
- Encrypted packets from the relay start with the SAME peer_tag followed by msg_key; a relay response is distinguished only by the 0xFF*12 marker at offset 16 (a real msg_key is random, so no ambiguity in practice).
- The relay does not authenticate anything other than the tag; it forwards datagrams carrying a tag to the OTHER party registered for that tag (observed behaviour from client code: INIT sent to all relays; first valid packet back decides which relay is current).

### 2.5 Stream data packet (type 4 = PKT_STREAM_DATA) payload  (HandleAudioInput :1186-1213; parse :2531-2578)
```
u8  stream_byte = stream_id(1) | flags      // low 6 bits id; 0x40 = LEN16, 0x80 = HAS_MORE_FLAGS (reserved, don't set)
if LEN16:  u16 len_and_flags  (low 11 bits = Opus length; 0x8000 KEYFRAME, 0x4000 FRAGMENTED, 0x2000 EXTRA_FEC; set none)
else:      u8  len            (used when opus len <= 255)
u32 pts    // ms timestamp; first packet 0, then += 60 per packet (audioTimestampOut += frameDuration(60), :1250)
u8[len] opus_packet
```
Sender chooses LEN16 only if len>255 or extra-FEC. Receiver: `sdlen&=0x7FF` (:2557). Bounds: `offset+sdlen<=len` else drop.
Fragmented/EXTRA_FEC/video not used. If we receive EXTRA_FEC (0x2000) we must still parse: after the primary frame comes `u8 fec_count; fec_count x {u8 dlen; u8[dlen]}`; these are redundant older frames (pts-(count-j-1)*60); ignorable.
Sample header for a 60 ms NB frame of 40 bytes: `01 28 <pts u32 LE> <40 opus bytes>`.

## 3. Audio coding

Sender (OpusEncoder.cpp 2.4.4/public):
- `opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP)`, complexity 10, `PACKET_LOSS_PERC=1` (later set 0..20 from loss stats), `INBAND_FEC=1`, `SIGNAL_VOICE`, bandwidth AUTO (2.4.4: FULLBAND), bitrate requested 20000 initially then (ServerConfig defaults, VoIPController.cpp:223-232): init 16000, max 20000, min 8000, step +/-1000; GPRS/EDGE 8000; data saving 8000. VBR default on (no OPUS_SET_VBR call), no DTX (SetDTX exists; a 1-byte result is dropped "DTX" and not sent: OpusEncoder.cpp Encode()).
- Capture is 20 ms mono @48 kHz (960 samples) chunks; **three chunks are concatenated and encoded as ONE 60 ms Opus packet** (`frameDuration=60`, RunThread: `Encode(frame, 960*packetsPerFrame)`; VoIPController.cpp:1281 `SetOutputFrameDuration(stream->frameDuration)` with frameDuration=60). libopus therefore emits a single 60 ms packet (code 0 SILK, or code 3 for hybrid/CELT).
- No explicit sample rate in the wire format. The Opus TOC byte carries bandwidth (NB/MB/WB/SWB/FB) and frame size.

Receiver (OpusDecoder.cpp):
- `opus_decoder_create(48000, 1)`; calls `opus_decode(dec, pkt, len, out, packetsPerFrame*960 = 2880, fec)`. Playback unit is 60 ms (decoder `SetFrameDuration(60)`, `packetsPerFrame=3`).
- **Any bandwidth is fine**: libopus decodes a narrowband (8 kHz) Opus stream at 48 kHz output. So you may encode with `opus_encoder_create(8000, 1, OPUS_APPLICATION_VOIP)` (TOC will signal NB) and the Telegram peer plays it. Verified by decoder code; not by a live test.
- **Frame size is the hard constraint: you MUST send exactly 60 ms per Opus packet** (480 samples at 8 kHz / 960 at 16 kHz / 2880 at 48 kHz), with pts +60 per packet. A 20 ms or 40 ms packet would decode to only 960/1920 samples while the player assumes 2880 -> chopped audio / jitter-buffer mis-timing. libopus >= 1.2 supports 60 ms directly in opus_encode (SILK). Use `OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND)`, `OPUS_SET_BITRATE(8000..12000)`, `OPUS_SET_INBAND_FEC(1)`, `OPUS_SET_PACKET_LOSS_PERC(5)`, VBR on, DTX off, complexity per CPU budget (N79 ARM11 369 MHz: complexity 0-2 likely needed; unmeasured).
- Receiver side for us: you receive 60 ms packets (also sometimes 20/40 ms playback "stretching" is done by the receiver's resampler, not on the wire). Decode with an 8 kHz decoder (`opus_decoder_create(8000,1)`, frame_size 480; opus resamples internally). Handle packet loss by `opus_decode(NULL,0,..)` PLC and optionally decode FEC from the next packet (`decode_fec=1`) as libtgvoip does (OpusDecoder.cpp:222-236).
- Jitter: the peer's jitter buffer is keyed on `pts` (JitterBuffer.cpp PutInternal :220-300): initial buffering `jitter_initial_delay_60`=2 packets (VoIPController.cpp:2440-2447; Server config may override); `nextTimestamp = first_pts - 60*minDelay`. First pts may be 0; always monotonic +60; keep sending even when silent (no DTX support needed) to avoid peer treating gaps as loss (peer applies PLC / stretching).
- Packet size limit: peer jitter slot `JITTER_SLOT_SIZE` (JitterBuffer.h, 1024 expected); at <=20 kbps a 60 ms packet is ~150 bytes. Keep Opus payload < 255 B so the 1-byte length path is valid; overall datagram well under MTU 1100 (DEFAULT_MTU).

## 4. Timing, acks, keep-alives, termination

State machine of the reference controller: WAIT_INIT(1) -> WAIT_INIT_ACK(2) -> ESTABLISHED(3) / RECONNECTING(5) / FAILED(4) (VoIPController.h:63-67).
- **Start**: at `Connect()`, send thread posts `SendInit` immediately (:1045). `SendInit` (:1536): ONE new seq (`initSeq=GenerateOutSeq()`) shared by all endpoints; INIT sent encrypted+tag-prefixed to EVERY UDP relay; state WAIT_INIT->WAIT_INIT_ACK; re-posted every **0.5 s** while still WAIT_INIT_ACK (each retry takes a NEW seq via GenerateOutSeq in the repeat call). Init timeout `initTimeout` (30 s): FAILED/ERROR_TIMEOUT (:1010-1016).
- There is NO generic retransmit queue in v>=6 for INIT/INIT_ACK: INIT is retried by timer; INIT_ACK is sent once per received INIT (the peer re-INITs every 0.5 s until it gets one; so ANSWER EVERY INIT you receive, even duplicates with new seq). `receivedInit` first INIT sets peerVersion (:2305).
- Both sides send INIT simultaneously (no caller/callee role in the media handshake). Complete handshake = we received INIT_ACK (receivedInitAck) AND we received INIT (receivedInit). Audio output/capture starts when both are true (:2381-2396, 2457-2464) -- `HandleAudioInput` drops audio until `receivedInitAck` (:1176). To be safe, start sending audio after INIT_ACK received; start decoding on any STREAM_DATA.
- ESTABLISHED: set 1.5 s after INIT_ACK (`established_delay_if_no_stream_data`, :2467) or 0.5 s after first STREAM_DATA (:2490-2495). Doesn't change wire behaviour.
- **Acks**: every outgoing header carries ack_seq (=highest seq received) + 32-bit mask (reliable for loss accounting only). Sender regards an outgoing packet lost if unacked for `max(2*rtt, 0.1 s)` (:3925-3935); only affects congestion control (bitrate step +/-1000 bps, `UpdateAudioBitrate` every 0.3 s, `UpdateCongestion` every 1 s). A minimal client may ignore loss accounting entirely. Peer might (a) reduce ITS bitrate for us only if WE ... no: peer's controller adapts its sending based on acks WE send: if we never send packets carrying acks, the peer's `waitingForAcks`/congestion logic will see losses and throttle its bitrate to the minimum 8000 and enable "shitty internet mode" (extra EC). Since we send audio every 60 ms in both directions, every packet carries acks; fine.
- **NOP ack**: if `unacknowledgedIncomingPacketCount > unack_nop_threshold(10)` with no outgoing packet, send PKT_NOP (:2289-2293, ServerConfig default 10 at :241). With continuous audio each way (16.7 pkts/s) no NOPs are needed. Send NOP only if we are muted/not sending audio.
- **Ping/keep-alive**: `SendRelayPings` every 2 s checks each endpoint; sends PKT_PING (no payload) to an endpoint if >=10 s since last ping (:3586-3625) -- ONLY when ESTABLISHED/RECONNECTING and >1 endpoint exists. Peer answers PONG with `u32 ping_seq` (:2594). Recommended minimal: send PING every 10 s to the current relay (extra safety against NAT timeout; N79 operator NAT mappings expire in 30-60 s on UDP if silent); reply PONG to every PING.
- **Timeouts**: if no valid packet received for `reconnecting_state_timeout` 2.0 s (:3755) -> RECONNECTING (UI only, resets UDP availability, restarts UDP pings 0.5 s). If `recvTimeout` (20 s default) -> FAILED/ERROR_TIMEOUT (:3764-3795). A valid packet during RECONNECTING returns to ESTABLISHED (:2063).
- **Relay switching**: if a packet arrives (valid decrypt) from a different relay while currentEndpoint is not better, controller switches `currentEndpoint` to that relay (:2250-2260; INIT also sets it :2387-2393). Minimal client: send INIT to all relays, then fix on the relay from which the first valid packet (INIT or INIT_ACK) arrived; reply on THAT relay (reply INIT_ACK to the endpoint the INIT came from: peer INIT_ACK path uses endpoint 0 => currentEndpoint; the libtgvoip INIT_ACK is sent via `currentEndpoint` after it's updated at :2387 -- effectively the relay that carried the INIT).
- **Termination**: there is NO in-band hang-up packet in libtgvoip. A call ends via MTProto `phone.discardCall` (reason phoneCallDiscardReasonHangup/Busy/Disconnect/Missed) and the `updatePhoneCall` phoneCallDiscarded from the peer. Locally: stop sending; the peer's controller dies from the API update. If the media stalls the peer's own `recvTimeout` (20 s) fails the call. Also call phone.receivedCall/phone.setCallRating/phone.saveCallDebug optionally (not media).

## 5. Minimal implementation plan

### 5.1 Components
1. UDP socket to relay IP:port (IPv4), peer_tag per relay.
2. Crypto: SHA-256 (KDF2 + msg_key), AES-256-IGE (key from sha256, 32B iv). SHA-1 not required (long-format only). Random for padding (not security-critical; use any PRNG).
3. Packet layer: seq counter (start 1), recent-incoming set (128) + ack mask, lastRemoteSeq.
4. Opus 8 kHz encoder (60 ms) / decoder.
5. Timers: 0.5 s INIT retry, 60 ms audio tick, 10 s ping, 0.5 s UDP pings optional, 2 s/20 s timeouts.

### 5.2 State machine
```
IDLE --start--> WAIT_INIT_ACK: send INIT to all relays (seq=n, same n); repeat every 0.5 s (new seq each repeat)
  on valid pkt from relay R:
      lock current relay := R (if not yet locked)
      type INIT     : record peerVersion(u32 at P[payload]); require ver>=8..9 and its min<=9; reply INIT_ACK (our fixed 18 bytes) to R (every time); receivedInit=1
      type INIT_ACK : parse: u32 ver,u32 minVer,u8 n, streams[] {id,type,u32 codec,u16 dur,u8 enabled}; remember audio stream id (peer's id for its outgoing audio; incoming data is matched by this id, normally 1); receivedInitAck=1
  when receivedInitAck: start audio send loop (also fine to wait for receivedInit)
ESTABLISHED: every 60 ms send STREAM_DATA(stream 1, pts+=60); decode incoming STREAM_DATA; reply PONG to PING; NOP if >10 unacked and not sending
  no valid packet 2 s -> RECONNECTING (UI); 20 s -> FAILED
END: stop sending; phone.discardCall via MTProto.
```
Note: if only we send INIT_ACK before receiving the peer's INIT_ACK we still keep INIT retries until INIT_ACK arrives.

### 5.3 Pitfalls
- Byte order: all little-endian. 'OPUS' = 0x4F505553 as u32, so the wire bytes are 53 55 50 4F.
- Padding rule: padLen must end up 16..31 and the receiver REQUIRES `decryptedLen - innerLen >= 16` where innerLen excludes the 2-byte length field -> total padding >= 14. Use the libtgvoip rule exactly.
- msg_key hashes the WHOLE decrypted buffer (length field + data + padding), not just the data. x in the msg_key slice (88+x) uses the SENDER's x; KDF2 offset uses the same x. Receiver mirrors with its own `isOutgoing?8:0`. Mixing sender/receiver x is the #1 bug.
- IGE iv layout: 32 bytes `aes_iv`; IGE needs (iv_y0 = iv[0..16), iv_x0 = iv[16..32)) (OpenSSL `AES_ige_encrypt` convention, = MTProto).
- Short vs long format must match peer: with max_layer 92 and peer in-band version 9 both sides use short; do NOT send fingerprint/length.
- Frame duration: 60 ms ONLY; sample rate is not signalled; NB 8 kHz Opus accepted by libopus-48k decoder.
- Always answer INIT with INIT_ACK even if already acked (peer retries every 0.5 s with a new seq; also duplicates are dropped silently by seq-window, so a retry will have new seq).
- Duplicate window: seq must not repeat; seq increments for every packet including PING/NOP/ACKs.
- UDP datagram max: decryption buffer in peer is 1500; keep < 1100.
- Do not send audio with extras flags unless properly formatted; extras length byte = len(type+data), max 254.
- Reflector pongs/tl packets (FF-marker) arrive unencrypted from the same ip:port and must not be fed to AES (check marker before decrypting; a 32-byte-or-more packet with FF*12 at offset 16).
- If the peer sends video-capable INIT flags (bit 2/3) there are extra bytes after the codec list; ignore. Our INIT_ACK must not advertise video streams.
- PKT_STREAM_DATA from the peer might use LEN16 with 0x4000/0x2000/0x8000 flag bits in the length; mask with 0x7FF and honour EXTRA_FEC trailer when sizing/skipping (only matters for X2/X3 multi-frame).
- Server config (JSON string pushed by `help.getConfig` `voip_config`/`phone.getCallConfig`) can tweak thresholds (jitter delays, bitrates); defaults above apply otherwise. Not required.

## 6. Interoperability: what is verified and what is not

Verified from source (reading code): packet framing, crypto/KDF2/msg_key, header layout, INIT/INIT_ACK layouts, stream data layout, encoder/decoder rates, 60 ms hard-coding, relay UDP ping/reply formats, timers, termination (no in-band hangup), wire identical in 2.4.4 and public.
Not verified (no live server / no capture):
- What Telegram's server returns as `phoneCall.protocol.library_versions` when caller advertises only ["2.4.4"] while callee advertises many (server-side logic is closed). Clients take element 0 (Android VoIPService.java:3615/3630; iOS Meta::Versions iterates a std::map -> lexicographic order, so a client advertising ["10.0.0","11.0.0","2.4.4","2.7.7",...,"9.0.0"]), i.e. client-side order is NOT "highest first"; server likely returns the intersection (probably preserving the caller's order). If the callee never claims 2.4.4 the call will fail at signalling.
- Whether current builds still register the legacy engine: Android still has `if(!"2.4.4".equals(version))` special-case in Instance.makeInstance and tgcalls master still ships `InstanceImplLegacy::GetVersions() -> "2.4.4"`; Telegram Desktop/iOS also link tgcalls/legacy (iOS `versionsWithIncludeReference` iterates all registered, includes legacy). Likelihood legacy remains in clients today (late 2026): high but declining -- Telegram has been moving to v2/v4.0.0+ (WebRTC-based, `tgcalls/v2`: 4.0.0+) with signalling via `phone.sendSignalingData`, and legacy exists mainly for old peers. Risk 1: Telegram could drop 2.4.4 at any release. Risk 2: server-side `phoneCall.protocol` might refuse when no common version ("CALL_PROTOCOL_LAYER_INVALID" or similar). Risk 3: P2P attempts / reflector API changes.
- min_layer value: 65 recalled from Android code, not re-fetched.
- Exact initial server config values for jitter and bitrate (ServerConfig defaults taken from VoIPController.cpp:223-241; real values from `phone.getCallConfig`).
- Behaviour of ARM11 N79 CPU with Opus at complexity > 2; AES-IGE+SHA256 per 60 ms packet cost estimates not measured (SHA256 over ~200 B + 2 x SHA256 of 100 B + AES of ~200 B per packet each way: negligible).
- Whether relay forwards unencrypted TL packets only to the sender (assumed from `SELF_INFO`).

Verdict: protocol is compact and fully specified by source; crypto is straightforward MTProto-2-style. Interop risk is dominated by (a) the version-negotiation at the signalling layer (is 2.4.4 still accepted by Telegram servers/clients), (b) any mistake in KDF2/IGE (testable offline against libtgvoip), and (c) the strict 60 ms Opus framing. Moderate risk overall; low risk for the media layer once signalling lands on "2.4.4".
