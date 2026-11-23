# Video on the 2.7.7 call: feasibility and implementation spec

Researched 2026-11-23. Companion to CALL-277-SPEC.md (read its sections 0-4 first; same pin: tgcalls 545f5ae599f8282e1ae3f38aaff166d179d75703). Nothing here is implemented. Items marked UNVERIFIED could not be confirmed from the sources fetched (Message.cpp, MediaManager.cpp, CodecSelectHelper.cpp, VideoCaptureInterface.h at the pin; search results); they MUST be confirmed with a packet capture against an official app before code is written.

## 0. Verdict

Feasible, medium-large. Audio is already carried as plain RTP inside AudioData(5) messages over the AES-256-CTR TRANSPORT EncryptedConnection; video uses the same pipe (VideoData(6), same framing, no SRTP/DTLS). New work is: (a) signalling of VideoFormats/RequestVideo/RemoteMediaState/VideoParameters, (b) H.264 RTP packetizer/depacketizer (FU-A, STAP-A, SPS/PPS handling), (c) a minimal RTCP (PLI, NACK, probably transport-cc feedback tolerance), (d) tgvideo.exe loop for camera->encoder and chunk->decoder->screen, (e) UI. The device side is proven; the risk is almost entirely interop (does the official peer accept our baseline level 1.0 QCIF format and does it keep sending if we never send transport-cc feedback).

## 1. Negotiation

### 1.1 requestCall / acceptCall
- `phone.requestCall#42ff96ed flags video:flags.0?true user_id random_id g_a_hash protocol` : set flags.0 (video) when WE start with video. When the peer starts a video call, `phoneCallRequested` has flags.5? video=true (flag bit UNVERIFIED; check the TL scheme layer in use in tgclient.py; tdesktop `PhoneCallRequested.is_video()`).
- phoneCallProtocol stays `udp_p2p=1 udp_reflector=1 min_layer=65 max_layer=92 library_versions=["2.7.7"]` (as today). The `video` flag only controls ringing UI/initial camera; the actual media negotiation is entirely in-band (below), so an audio call can be upgraded to video at any time by either side (RemoteMediaState/RequestVideo).
- CALL-VERSIONS.md: `"2.7.7".compareTo(v0) <= 0` gates video on Android, so 2.7.7 is the oldest version with video. 2.4.4 (legacy) has no tgcalls video.

### 1.2 Signalling messages (MediaManager.cpp / Message.cpp at pin)
Message framing (Message.cpp): `u32 seq` (byte order not shown on the fetched page; rtc::ByteBuffer default = big-endian, UNVERIFIED but matches our existing c277_msg.c, which already works for audio) | `u8 id` | body. Strings = `u32 len | bytes`. IDs per CALL-277-SPEC sec 3 table (c277_msg.c already parses them):

| id | name | channel | ack | body |
|---|---|---|---|---|
| 2 | VideoFormats | signalling | yes | `u8 nFormats; nFormats x { str name; u8 nParams; nParams x {str key; str value} }; u8 encodersCount` (encodersCount <= nFormats, reader rejects otherwise) |
| 3 | RequestVideo | transport | yes | empty |
| 4 | RemoteMediaState | transport | yes | `u8 = (video<<1)|audio`; audio 0=Muted 1=Active; video 0=Inactive 1=Paused 2=Active; video==3 rejected |
| 6 | VideoData | transport | no | `u16 len | rtp` when several messages are packed in one packet, else raw RTP to end of packet (same rule as AudioData 5) |
| 8 | VideoParameters | transport | yes | `u32 aspectRatio*1000` (e.g. 1333 for 4:3, 1222 for 176x144 = 11:9) |
Note (existing doc line 105 says VideoFormats on signalling; MediaManager::start sends it via `_sendSignalingMessage`, confirmed).

Sequence of a video call (MediaManager.cpp):
1. At start each side sends `VideoFormats{_myVideoFormats}` on SIGNALING. Peer computes `ComputeCommonFormats(mine, theirs)` and `AssignPayloadTypesAndDefaultCodecs`. If we never send VideoFormats, the peer has no common set and no video flows (current audio-only behaviour). **We must send it to enable video.**
2. After the connection is up: `VideoParameters(aspect)` + `RemoteMediaState` over TRANSPORT.
3. Sender turns the camera on -> sends `RemoteMediaState{video=Active(2), audio=...}`; receiver (`remoteVideoStateUpdated`) calls `configureSendingVideoIfNeeded` and starts accepting/decoding. Pause = video 1, off = 0. State byte for audio-on + video-on = 0x05; audio-on video-off = 0x01.
4. RequestVideo(3): a peer without video capture asks the other to start sending (ours: send it when the user taps "ask for video"; on receive, start camera if the user accepts).
5. `VideoParameters` receive: `aspect = v/1000.0`, passed to capture `setPreferredAspectRatio`: peer crops its camera to our aspect. We should send 1222 (11:9) so QCIF is not letterboxed; UNVERIFIED that the peer encoder then emits exactly 176x144 (it will pick resolution by bandwidth/ladder; expect 192x144..320x240 style sizes, see sec 3).

### 1.3 Our VideoFormats message (proposed)
`nFormats=1; name="H264"; params: {"level-asymmetry-allowed":"1","packetization-mode":"1","profile-level-id":"42e00a"}`? Note official webrtc H264 format is `profile-level-id=42e01f` (ConstrainedBaseline L3.1) with packetization-mode 1 (UNVERIFIED which exact variants Telegram lists; iOS typically lists 42e01f and 640c1f...). `encodersCount = 1` (number of formats we can ENCODE; remaining are decode-only). Decision rule: `IsSameCodec` in webrtc compares H264 by profile (H264IsSameProfile, level ignored) and packetization-mode, so advertise `42e01f` + `packetization-mode=1` (the strongest-compatibility value) even though our hardware is L1.0; level asymmetry means each side may send at its own max level, the receiver level only guides the encoder (the official encoder will happily downscale if the SDP says a smaller maxfs, but 2.7.7 has no maxfs/max-fs signalling: UNVERIFIED). Therefore expect the official peer to send up to its ladder (e.g. 640x480 or 320x240 at 15-30 fps) that our QCIF-only decoder CANNOT decode. See 3.2 for the mitigation (must be tested first).

### 1.4 Payload type assignment (CodecSelectHelper.cpp)
`kFirstDynamicPayloadType=96`, last 127. Each common format gets next PT; each non-FEC codec is followed by an RTX codec PT (apt = codec PT). Then RED and ULPFEC appended, then FlexFEC. Common list is sorted by `CompareFormats` (name, then params), identical on both sides, so PTs are deterministic; if H264 is the only common format: H264=96, RTX=97, then RED/ULPFEC/FlexFEC (exact order UNVERIFIED, probably RED=98 ULPFEC=99 FlexFEC=100). **Our client must reproduce this arithmetic** (or, simpler, accept any PT on receive and, on send, use the PT whose number the peer would assign: 96 when we offer only one H264 format and the peer supports H264 as the only common format with us, regardless of its extra VP8/VP9/AV1 entries, because common = intersection with our list). Sort ordering means if we offer exactly one format the intersection is exactly one entry: PT 96. RTX/RED/FEC we do not send; we ignore PT 97+ on receive (peer sends RTX only on NACK of video we sent... only if we NACK; we need not).

## 2. RTP and RTCP

### 2.1 SSRCs (MediaManager.cpp constants)
audio in/out = 1/2, FEC audio 5/6; **video incoming=3, outgoing=4**, video FEC incoming/outgoing = 7/8 (from the receiver's point of view: what a peer sends as "outgoing" is our "incoming"). Caveat: names are per-side; the peer's video outgoing SSRC 4 is OUR incoming 3? Existing audio working with 1/2 must be mirrored: audio the peer sends arrives with SSRC 2 (their outgoing) in practice or 1 depending on role (check c277_rtp.c, which already handles this); apply the same swap to video: we SEND with ssrc 4 and RECEIVE ssrc 3 if the audio rule is "caller/callee symmetrical", UNVERIFIED, so accept any SSRC on receive and do not rely on it. SSRC group: FlexFEC FEC-FR group {videoOutgoing, fecOutgoing}; no RTX SSRC group in this file (RTX SSRC derived by webrtc; UNVERIFIED, ignore RTX).

### 2.2 H.264 packetization (webrtc standard RFC 6184, packetization-mode=1)
- RTP header 12 bytes, V=2, PT=96 (sec 1.4), clock 90000, marker bit on the last packet of a frame, timestamp same for all packets of a frame, sequence number +1 per packet.
- Payload MTU: keep <= 1100 bytes payload (relay path and AES-CTR packet overhead; audio packets are far smaller). At 60 kbit/s QCIF a P frame is ~500-1500 bytes, IDR ~3-6 kB, so FU-A is needed for IDR.
- Single NAL: payload = NAL (types 1 non-IDR, 5 IDR, 7 SPS, 8 PPS).
- STAP-A (type 24): `0x18 | { u16 size | NAL }*` use for SPS+PPS (+ IDR if it fits). webrtc sender prepends SPS/PPS to every IDR (we do too; our encoder already emits them with IDR).
- FU-A (type 28): byte0 = `(NRI<<5)|28`, byte1 = `S<<7|E<<6|R<<5|origType`, then fragment. S on first, E on last.
- Convert encoder Annex-B-like output to NAL units (strip 00 00 01 / 00 00 00 01 start codes) in tgvideo.exe (native), emitting length-prefixed NALs through the chunk; Python/C builds RTP.
- Receive: reassemble FU-A by seq order; discard frame on gap and send PLI (2.3). Rebuild Annex-B (start code per NAL) for the 0x102073ef decoder. Always feed SPS+PPS before the first IDR.
- STAP-B/MTAP/FU-B not used by webrtc.

### 2.3 RTCP
Carried as ordinary RTCP packets inside the same RTP stream? In tgcalls V0/V1 there is no separate RTCP port: webrtc is configured with `rtcp-mux` and RTCP travels as plain compound packets in the same AudioData/VideoData message payload (UNVERIFIED: which message id carries RTCP; the demux is by RTP header byte1 in 192..223 or PT 72-79 per RFC 5761; in tgcalls Manager/MediaManager, packets received via `receivePacket` are passed to `Call::Receiver()->DeliverRtpPacket` / `DeliverRtcp`). Test by capturing what the official peer sends with video on.
Feedback advertised for every non-FEC video codec (CodecSelectHelper.cpp AddDefaultFeedbackParams): `goog-remb`, `transport-cc`, `ccm fir`, `nack`, `nack pli`. Therefore:
- PLI (RFC 4585 PSFB FMT=1, PT=206): 12 bytes `0x81 0xCE 0x0002 | senderSSRC | mediaSSRC`. Send on first video packet (to get an IDR) and after loss. Throttle to 1 per second.
- FIR (PSFB FMT=4 PT=206): optional; accept PLI-only. If the peer sends PLI/FIR to us: force an IDR (send `IDR request` to tgvideo.exe via 47012).
- NACK (RTPFB FMT=1 PT=205): `0x81 0xCD len | ssrc | ssrc | {u16 pid, u16 blp}`. Peer sends NACK for lost packets; we may ignore (a recovery by next IDR costs ~1 s) or keep a 64-packet history and resend. Send NACK ourselves: optional, not in first stages.
- REMB (PSFB FMT=15, 'REMB'): peer may send; ignore. We need not send, but the peer bitrate estimate relies on transport-cc below.
- **transport-cc (RTPFB FMT=15)**: `kTransportSequenceNumberUri` is registered with ids audio=1, video=2 (MediaManager.cpp). Official senders include the extension on RTP and expect transport-wide feedback packets; if we never send them the sender's bandwidth estimator falls back to its start bitrate (400 kbit/s start, 64 min, max 800/2000: kCodecParamStartBitrate=400, Min=64, Max=800 or 2000) and treats feedback absence as loss/overuse, UNVERIFIED how aggressively it drops. Audio already works without feedback (CALL-277-SPEC sec 6 allows "no transport-cc"), so first test video without it; fall back to sending the peer a coarse transport-cc feedback (needs ext parse: one-byte header, id 2, 16-bit transport seq, plus arrival times in 250us ticks) only if the peer stops sending video after seconds.
- `rtcp.reduced_size=true, remote_estimate=true` set on both audio and video; reduced-size RTCP means PLI/NACK may be sent without a leading SR/RR. Still send an RR (or SR for our send stream) every ~1-5 s for good measure: UNVERIFIED if peer needs it.

### 2.4 RTP header extensions (MediaManager.cpp)
- Video: id 2 transport-wide-cc (`http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01`), id 3 video-orientation (`urn:3gpp:video-orientation`, CVO), id 4 timestamp offset (`urn:ietf:params:rtp-hdrext:toffset`), the last two only under ProtocolVersion::V1. **2.7.7 is V0 => only id 2 (transport-cc) is registered for video; no CVO, no toffset.** No abs-send-time anywhere in MediaManager.cpp.
- Extension format: RFC 8285 one-byte: `0xBE 0xDE | u16 words | {id<<4 | (len-1), data...}`; X bit in RTP header. Our sender can omit extensions entirely (legal). On receive, skip them via the X bit and word count.

### 2.5 Transport
VideoData(6) goes through exactly the same TRANSPORT EncryptedConnection path as AudioData(5): message = `u32 seq | u8 6 | rtp`, encrypted with AES-256-CTR/SHA-256 KDF as CALL-277-SPEC sec 3, wrapped in the reflector DATA datagram (sec 2.2) and relayed. UDP datagram size: keep the whole encrypted packet below ~1200 bytes (reflector header 24 + EC overhead + message header 5 + RTP 12 + payload 1100). Up to ~15-25 packets/s extra at 60 kbit/s: negligible for the phone's UDP path, but the Python side must not sit in the packet loop (see 5).

## 3. Codec profile / resolution

### 3.1 What the apps offer
CodecSelectHelper.cpp: priority list `AV1, H265 (unless WEBRTC_DISABLE_H265), H264, VP8, VP9` filtered by `platform->supportsEncoding`; decoders unfiltered. The first common encoder on each side defines `myEncoderIndex`. H.264 `profile-level-id` is NOT inspected in this code (matching is by `IsSameCodec`, defined in webrtc: for H264 compares name + `H264IsSameProfile` + packetization-mode; level ignored). The exact fmtp list iOS/Android advertise is not in the fetched files: UNVERIFIED (expect 42e01f/42001f/640c1f with packetization-mode 1; hardware H.264 on Android is only offered when the device encoder qualifies).
Consequences:
- If the peer offers H265/AV1/VP8 AND we offer only H264, common = {H264}: good. If the peer's Android lacks H.264 hardware encoding, `supportsEncoding(H264)` may be false for sending but decoding is still advertised; the common-format code needs the peer to both encode and decode? `ComputeCommonFormats` keeps formats supported by both lists (lists contain encoders then decoders-only entries via encodersCount): video from the peer to us needs peer ENCODER + our decoder. UNVERIFIED which side's list index covers this; test: if the peer cannot hardware-encode H.264, expect no video from them (software openh264 is not used by Telegram Android; iOS uses VideoToolbox H.264 always).
- Baseline level 1.0 / QCIF as an advertised profile: webrtc ignores the level in profile matching, so `42e01f` and `42e00a` are the same codec; the receiving decoder is trusted to be able to handle any resolution, there is no max-fs in the Telegram message. So we can advertise honestly (`42e00a` = L1.0) but cannot constrain the peer's resolution via negotiation. (UNVERIFIED if Telegram's encoder reads level-asymmetry/profile-level-id to cap its output: webrtc's H264 encoders use the REMOTE profile only for profile selection.)

### 3.2 Resolution constraint of the phone (QCIF-only decoder 0x102073ef)
This is the main risk. The peer's encoder adapts resolution to bandwidth (webrtc quality scaler / bitrate ladder). At low available bandwidth (<~80 kbit/s) webrtc downscales to 160x90..240x180 class sizes; at the default start bitrate 400 kbit/s it sends 640x480 / 480x360 / 320x240. Mitigations, in order:
1. Cap bandwidth: send REMB (PSFB FMT=15) with 80-100 kbit/s so the peer scales down, and/or transport-cc feedback that reports a low receive rate. REMB advertised in feedback list (`goog-remb`) and `remote_estimate=true`; whether tgcalls' send-side BWE honours receiver REMB when transport-cc is also negotiated is UNVERIFIED (modern webrtc ignores REMB when transport-cc is active). Test first.
2. VideoParameters aspect 1222 does not set size.
3. Hardware/SW fallback: the SPS tells the size; if the incoming SPS is larger than 176x144 we cannot decode on 0x102073ef; show "video not supported at this size" and keep audio. Fallback: use 0x10204bfc hardware decoder for RECEIVE-ONLY mode when camera is off (it cannot run while camera captures): receive-only video call (we see them, they see nothing) supports larger frames (device-dependent; N79 HW decoder handles CIF/VGA? UNVERIFIED on device). This is a good first milestone because it needs no encoder.
4. Last resort: format list ordering/params that make the peer pick a different profile won't help; the peer's resolution is not negotiated.
Our outgoing QCIF 176x144 @15 fps ~60 kbit/s is accepted by any webrtc H.264 decoder (decoder reads SPS; resolutions need not be multiples of 16 beyond cropping; 144 = 9x16, 176 = 11x16: fine). Receiver display of low-res is upscaled. Baseline L1.0 with 1 reference frame, no B-frames: compatible with VideoToolbox/MediaCodec decoders (decoders accept any L <= their max).

## 4. Orientation and rotation
- 2.7.7 = V0: the `urn:3gpp:video-orientation` extension (id 3) is NOT negotiated and V0 frame-rotation rewrite is commented out in VideoSinkInterfaceProxyImpl::OnFrame (MediaManager.cpp). Therefore **rotation must be baked into the pixels**: the sender rotates frames to upright before encoding; the receiver displays as decoded. Peers send already upright video (the official apps rotate before the encoder on V0), UNVERIFIED but implied by the absence of the extension in V0.
- Our side: N79 camera in portrait use gives 144x176 or landscape 176x144 depending on UI mode. Easiest: use the phone in landscape (camera natural 176x144) and display fit in the video view; the sender uses the sensor orientation as-is. If the peer displays rotated by 90 degrees, then rotate by software 90 degrees before encoding (176x144 -> 144x176; widths multiples of 16 desirable: 144x176 is OK) in tgvideo.exe (a 25 kB-per-frame byte shuffle, cheap) or on the encoder input via camera orientation API.
- Receive: if the peer is in portrait the frames may arrive e.g. 144x192/240x320: draw scaled/cropped to the screen in the UI (tgvdisp helper).
- Optional later: in V1 (5.0.0) CVO ext id 3: value byte: `0=0 deg,1=90,2=180,3=270` + camera/flip bits (C bit 0x08 front-facing, F bit 0x04 flip); not needed for 2.7.7.

## 5. Build plan

Sizes are estimates of NEW code.

Stage 0 (no code, 1-2 evenings): capture truth. Run tgcalls CLI (tools/cli/main.cpp per CLAUDE.md) or an official client against our existing 2.7.7 stack with logging in c277_msg.c to dump decrypted packets of a real VIDEO call (peer sends VideoFormats, RemoteMediaState, VideoData, RTCP). Settle every UNVERIFIED in sec 1-3: VideoFormats params, PT numbers, RTCP carrier message id, SSRCs, resolution the peer sends to a receiver that sends nothing, whether it needs feedback.
Stage 1 (native C in call277, ~350 lines + ~60 python): parse and keep VideoFormats/VideoParameters/RemoteMediaState(video bits)/VideoData in c277_msg/c277_session; emit our VideoFormats(H264 only), RemoteMediaState with the video bit, VideoParameters(1222); pass VideoData RTP payloads to Python/helper. Test: official app calling us shows "video requested", no crash, audio still fine.
Stage 2 (receive-only, highest value): RTP depacketizer (FU-A, STAP-A, SPS/PPS cache, loss detect) ~300 lines C in call277 (c277_h264.c), PLI sender ~60 lines, output Annex-B to the tgvideo.exe decode path through the shared chunk (extend tgvshared.h with a "rx frame" ring, ~100 lines in tgvideo.cpp), tgvdisp draws. Test against official app: first IDR decoded and displayed. Camera off here, so try 0x10204bfc (HW) for bigger frames and 0x102073ef (SW) for QCIF; the result of 3.2 decides how many users get video.
Stage 3 (send): tgvideo.exe emits NAL units from the encoder (already working) with a small header (flags idr, ts) in the chunk, ~150 lines; call277 packetizer (single/STAP-A/FU-A, marker, ts at 90 kHz, seq) ~200 lines; IDR on PLI/FIR (command over UDP 47012); 15 fps pacing, sending directly from native (do not route RTP through Python: Python 2.2 on 434 MHz ARM1136 cannot do 20-30 pkt/s with encryption comfortably alongside audio). Test: official app displays our QCIF picture; check rotation (sec 4).
Stage 4 (robustness): RTCP RR/NACK history/REMB-or-transport-cc tuning, RequestVideo, video pause/off messages, VideoParameters handling, bitrate cap, camera/decoder exclusivity switching (decoder 0x10204bfc vs camera conflict: pick the SW decoder in duplex mode, as proven), ~250 lines.
Stage 5 (UI): pys60/tgui.py CallView: video toggle button, remote video surface (tgvdisp), local preview optional (costs CPU), state text, ~150 lines Python; tgclient.py: requestCall video flag + acceptCall for incoming video call UI, ~60 lines.
Total ~1,100-1,300 lines native + ~250 Python, ~2x the stage-1-5 effort of a typical call feature. Python holds signalling/UI only; all per-packet work stays native.

## 6. Risks
1. Peer resolution larger than QCIF (sec 3.2): highest risk; may force receive-only HW decode or an "audio only, peer video unsupported" mode. Decide at stage 2.
2. Peer encoder may be H.264-less (Android without HW H.264 encoder), then it sends VP8/VP9 which we cannot decode; they get no video from us either unless they can decode H.264 (almost all can).
3. Bandwidth estimation without transport-cc feedback: peer might throttle to 64 kbit/s (fine) or stall (needs transport-cc sender).
4. CPU/memory: encoder + SW decoder + AES-CTR + audio on one 434 MHz core; frame pacing may need 10 fps fallback.
5. RTCP/PT/SSRC details UNVERIFIED until Stage 0.
6. Mode-switch glitches: camera open/close while a hardware decoder is active; UID/memory constraints of tgvideo.exe (see N79 UID registry, RetroTele owns E0-EF).
7. The `video` flag/TL layer details in requestCall/PhoneCallRequested are UNVERIFIED against our TL layer in tgclient.py.
8. The tgcalls pin is a 2026-10-27 snapshot; real peers on other builds might differ. Real servers were not observed by me.

## 7. Implemented in 0.14.0: send-only video (what the 2026-11-23 capture settled)

Capture facts (official app, plain RTP inside AES-CTR transport message id 6): PT 96 for the single common H264 format (we offer only `42e01f`, packetization-mode 1, level-asymmetry-allowed 1, which is in the peer's list), SSRC 3 for the callee and 4 for the caller (same split as audio 1/2), one-byte header extension id 2 (transport-cc seq, 2 bytes + 1 pad), STAP-A(SPS,PPS) then FU-A, marker on the last packet, RTCP SR (pt 200, 44 bytes with SDES CNAME "cname") about once a second and an empty RR for the audio SSRC, all in message id 6. The peer sent High 528x960 L3.1 first and 352x640 L2.2 in a second call (it downsizes; logged as `peerSPS`).

Data path: `tgvideo.exe` (camera + SW encoder 0x20001c13 + loopback decoder 0x102073ef for the self-view) sends every encoder unit as one UDP datagram `'V'+Annex-B` to `127.0.0.1:47014` (command `E 1`); `tgcallaudio.exe` packetizes natively (`native/call277/c277_video.c`: single NAL <= 1000 bytes, STAP-A SPS+PPS before each IDR, FU-A otherwise) and sends through the session. UDP was chosen over a shared chunk because units arrive as events in the helper's active scheduler (no polling, no seqlock), at 15 fps / ~60 kbit/s the load is below 40 KB/s, and the rest of the helper chain already uses localhost UDP. IDR requests go back as `K` to `127.0.0.1:47012` on PLI/FIR and on an early schedule (0.3, 1.5, 3.5, 6.5, 10 s after video starts). Python only sends `V1`/`V0` (CallAudio.set_video) and drives tgvideo.exe (`pys60/callvideo.py`).

Signalling when the user turns video on: VideoFormats (if not already sent) on the signalling channel, then (after it is acked, or 1.5 s) VideoParameters(1222) and RemoteMediaState{audio=1, video=2} on the transport channel; off sends video=0. The peer's RequestVideo is shown as "Peer asks for video (press 4)"; the camera never starts by itself.

Log (when `E:\retrotele_videocap.flag` exists): `retrotele_callvideo.txt` gets `peerSPS profile= level= size=WxH` for every peer SPS (repeats throttled to one per 10 s), once per second `vtx fps10= bps= pk= au= idr= drop= pli= nack= twcc= rr_frac= rr_lost=`, `video send ON/OFF`; `retrotele_callaudio.txt` gets a `v ...` line per second whenever video was used in the call. No keys or peer addresses are logged.

Not done / known gaps: no transport-cc feedback and no NACK retransmission history (we only count them), no rotation (`VIDEO_ROTATION_DEG` in callvideo.py is carried to tgvideo.exe but only 0 is implemented), nothing is shown of the peer's video.
