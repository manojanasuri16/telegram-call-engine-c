# Telegram call library versions vs. current official clients

Researched 2026-11-22 from public source (DrKLO/Telegram master, tgcalls submodule
pinned at 545f5ae599f8282e1ae3f38aaff166d179d75703, tdesktop dev, core.telegram.org docs).

## 1. Why the dialog appears

The dialog text ("Unfortunately you can't accept this call with this version of Telegram...
telegram.org/upgrade") is NOT in Android strings.xml, tdesktop lang files, or the iOS
Localizable.strings (searched all three). So it is not a client-side check; it is almost certainly
a server-localized error. Android has no client-side version check at all: it never compares
min_layer/max_layer or library_versions on an incoming call.

The server-side rule is documented for phone.acceptCall:

    406 CALL_PROTOCOL_COMPAT_LAYER_INVALID
    "The other side of the call does not support any of the VoIP protocols supported by the
     local client, as specified by the protocol.layer and protocol.library_versions fields."

Trigger (server, at phone.acceptCall, i.e. right after the user answers):
the callee's acceptCall.protocol.library_versions (what the Android build registers, see section 2)
has an EMPTY INTERSECTION with the caller's requestCall.protocol.library_versions, and/or the
[min_layer, max_layer] ranges do not overlap. Here the layer range 65..92 overlaps fine
(Android: CALL_MIN_LAYER = 65, Instance.getConnectionMaxLayer() = 92), so the failure is the
version-list intersection: ["2.4.4"] vs Android's list, which has no 2.4.4.

Android client facts (DrKLO master):
- VoIPService.java: CALL_MIN_LAYER = 65; acceptCall/requestCall/confirmCall all send
  `Collections.addAll(protocol.library_versions, NativeInstance.getAllVersions())`,
  udp_p2p = udp_reflector = true, max_layer = Instance.getConnectionMaxLayer() (= 92).
- After confirm, it does `Instance.makeInstance(privateCall.protocol.library_versions.get(0), ...)`
  (the version the server settled on). `"2.7.7".compareTo(v0) <= 0` gates video.
- Instance.makeInstance: `if (!"2.4.4".equals(version)) ContextUtils.initialize(...)` is a
  leftover special case for legacy; no legacy backend remains.
- JNI (jni/voip/org_telegram_messenger_voip_Instance.cpp) registers only:
  Register<InstanceImpl>, Register<InstanceV2Impl>, Register<InstanceV2ReferenceImpl>, and
  (aarch64 only) Register<InstanceV2PumpImpl>.
  getAllVersions() = tgcalls::Meta::Versions() (keys of the registered map).
  If Meta::Create gets an unknown version it returns nullptr and the JNI dereferences it
  (would crash), which is why the server must prevent selecting an unsupported version.
- jni/voip/CMakeLists.txt compiles NO tgcalls/legacy/* and no libtgvoip sources
  (only NetworkManager, EncryptedConnection, InstanceImpl, v2/*, v2_4_0_0, v2wasm/*).
  The legacy dir does not even exist in tgcalls at the pinned commit.
  => "2.4.4" (InstanceImplLegacy, libtgvoip) is NOT compiled into current Android.

Other clients:
- tdesktop (calls_call.cpp): kMinLayer = 65; sends MaxLayer = tgcalls::Meta::MaxLayer() and
  CollectVersionsForApi() = Meta::Versions() reversed. Creates the instance with
  protocol.library_versions[0] from the server's phoneCall. Handles request errors
  PARTICIPANT_VERSION_OUTDATED, CALL_PROTOCOL_LAYER_INVALID (-> "incompatible protocol"
  box), and ERROR_INCOMPATIBLE from the controller. No client-side intersection filter.
- iOS: not examined beyond string search (nothing found). Not verified.

## 2. Versions registered in current tgcalls (pinned commit used by Android)

| Version | Class | Android registered? |
|---|---|---|
| 2.4.4 | legacy/InstanceImplLegacy (libtgvoip) | NO (removed; not compiled) |
| 2.7.7, 5.0.0 | InstanceImpl | yes |
| 7.0.0, 8.0.0, 9.0.0, 12.0.0, 13.0.0 | v2/InstanceV2Impl | yes |
| 10.0.0, 11.0.0 | v2/InstanceV2ReferenceImpl | yes |
| 14.0.0 | v2/InstanceV2CompatImpl | not registered in Android jni |
| 18.0.0, 19.0.0 | v2wasm/InstanceV2PumpImpl (WASM core) | yes, aarch64 builds only |
| 3.0.0 | was InstanceImpl V1 | gone from GetVersions at this commit (Meta::Create still maps it) |
| 4.0.0 | was InstanceV2Impl | gone at this commit (old master of tgcalls still lists it) |

So the Android library_versions list today is approximately:
["2.7.7","5.0.0","7.0.0","8.0.0","9.0.0","10.0.0","11.0.0","12.0.0","13.0.0"] plus
"18.0.0","19.0.0" on arm64. (Map is std::map, so sorted alphabetically.) Exact list on a given
device not verified at runtime.

## 3. Transport/crypto per version

- 2.4.4: libtgvoip legacy. Own UDP reflector protocol: phoneConnection with peer_tag, custom
  packet header + AES-IGE/MTProto-2-style keyed from the call auth key, Opus frames, no ICE,
  DTLS or RTP. (Source file not available at pinned commit; from knowledge, not re-verified.)
- 2.7.7 / 5.0.0 (InstanceImpl, NetworkManager.cpp, EncryptedConnection.cpp, MediaManager.cpp):
  WebRTC ICE (cricket::P2PTransportChannel, ICE parameters/candidates exchanged through
  phone.sendSignalingData) as transport; on top, EncryptedConnection.cpp = custom
  AES-IGE-with-msg_key (PrepareAesKeyIv) message framing keyed by the call key, carrying
  RTP-ish audio/video packets from a WebRTC Call object. Reflectors act as TURN-like relays
  (credentials/tag in phoneConnectionWebrtc). Not the simple libtgvoip protocol.
  5.0.0 = same engine, newer ProtocolVersion; 2.7.7 forced to ProtocolVersion::V0
  and 3.0.0 to V1 in Meta::Create.
- 7.0.0 - 9.0.0, 12.0.0, 13.0.0 (v2/InstanceV2Impl.cpp, NativeNetworkingImpl.cpp,
  MtProtoDtlsTransport.cpp, ReflectorPort.cpp, SignalingEncryption.cpp,
  SignalingSctpConnection.cpp, v2_4_0_0/Signaling_4_0_0): full WebRTC PeerConnection,
  SDP-like signaling (ContentNegotiation) encrypted by SignalingEncryption, ICE with
  ReflectorPort (reflector as relay), DTLS handshake over MtProtoDtlsTransport (keyed from the
  call key), SRTP/RTP (Opus, VP8/H264), SCTP data channel. Version differences are feature
  flags in InstanceV2Impl (see version == "7.0.0"... branches).
- 10.0.0 / 11.0.0 (v2/InstanceV2ReferenceImpl.cpp): same family, reference implementation,
  also ICE/DTLS-SRTP-style with Reflector ports.
- 14.0.0 (InstanceV2CompatImpl), 18.0.0/19.0.0 (v2wasm, WASM core): further v2-family
  variants; not examined in depth.

Is any version newer than 2.4.4 still the simple libtgvoip-style reflector transport
(peer_tag + custom crypto + raw Opus, no ICE/DTLS/RTP)? NO, none that I found. Every
registered version uses WebRTC machinery (ICE at minimum; 7.0.0+ add DTLS/SRTP/SCTP).
The closest-to-simple is 2.7.7/5.0.0.

## 4. Assessment for a minimal relay-only client

No version is "easy". Ranking, least work first:
1. 2.7.7 (or 5.0.0): needs ICE-lite-ish STUN binding/TURN allocation against the reflectors
   (or at least STUN connectivity checks with the right ice-ufrag/pwd from signaling), plus
   EncryptedConnection framing (AES-IGE, msg_key, seq/ack, per-message types) and RTP-ish
   audio payloads, plus the signaling channel (phone.sendSignalingData) for ICE parameters/
   candidates. Effort: LARGE (comparable to reimplementing a subset of tgcalls
   InstanceImpl; could be reduced by porting EncryptedConnection.cpp + a minimal ICE agent).
2. 7.0.0+ : needs full ICE + DTLS (custom MtProto key-derived fingerprint) + SRTP + SDP-style
   negotiation + SCTP signaling. Effort: VERY LARGE.

Recommendation: target 2.7.7 as the only plausible path, treat as large. Alternative:
advertise only versions the peer app supports and accept that old libtgvoip (2.4.4)
interop works only with older/third-party clients (e.g. unofficial or very old official apps).

## 5. Not verified

- The origin/text of the dialog (no client string found; server-side inference from docs
  of CALL_PROTOCOL_COMPAT_LAYER_INVALID). The exact server algorithm is not public.
- Exact runtime versions list on a shipped Play Store build (used source master + pinned
  tgcalls commit; Play Store may lag/lead).
- iOS call version logic (only string search).
- Legacy 2.4.4 internals and wire format (source absent at pinned commit).
- Details of 14.0.0, 18/19.0.0, 10/11 reference transport beyond grep-level evidence.
- Whether the server also checks min_layer/max_layer here; ranges overlap in this case
  so it does not matter.
