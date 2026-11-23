#!/usr/bin/env python3
"""Independent Python implementation of every call277 primitive and datagram
layout (hashlib/hmac/zlib.crc32 + cryptography AES-CTR). Prints "<name> <hex>"
lines for fixed inputs; test_call277.c builds the same bytes and compares.
Fixed inputs must match test_call277.c (see comments)."""
import hashlib, hmac, struct, sys, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def out(name, b):
    print(name, b.hex() if b else "-")

def data(n, mul=3, add=1):
    return bytes((i * mul + add) & 255 for i in range(n))

# ---- primitives
for n in (0, 1, 55, 56, 63, 64, 65, 119, 120, 200):
    d = data(n)
    out("sha1_%d" % n, hashlib.sha1(d).digest())
    out("sha256_%d" % n, hashlib.sha256(d).digest())
    out("crc_%d" % n, struct.pack(">I", zlib.crc32(d)))
for kl in (0, 5, 64, 65, 100):
    out("hmac_%d" % kl, hmac.new(data(kl, 7, 2), data(77), hashlib.sha1).digest())
KEY32 = data(32, 5, 9)
for name, iv, n in (("a", data(16, 11, 4), 100), ("b", bytes([0xAB] * 8 + [0xFF] * 8), 70),
                    ("c", bytes([0xFF] * 16), 33), ("d", data(16), 1)):
    enc = Cipher(algorithms.AES(KEY32), modes.CTR(iv)).encryptor()
    out("ctr_%s" % name, enc.update(data(n, 13, 6)) + enc.finalize())

# ---- EncryptedConnection
K = bytes((i * 5 + 1) & 255 for i in range(256))

def sha(b): return hashlib.sha256(b).digest()

def seal(x, pt):
    mk = sha(K[88 + x:88 + x + 32] + pt)[8:24]
    a = sha(mk + K[x:x + 36]); b = sha(K[40 + x:40 + x + 36] + mk)
    key = a[0:8] + b[8:24] + a[24:32]; iv = b[0:4] + a[8:16] + b[24:28]
    e = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return mk + e.update(pt) + e.finalize()

def x_of(is_out, sig): return (0 if is_out else 8) + (128 if sig else 0)
def u32(v): return struct.pack(">I", v)
def string(s): return u32(len(s)) + s

RTP = bytes(0x10 + i for i in range(20))
# transport, we are the caller (A): see test_call277.c test_conn_vectors
a1 = seal(x_of(1, 0), u32(0x80000001) + b"\x05" + RTP)
a2 = seal(x_of(1, 0), u32(0x40000002) + b"\x04\x01")
a3 = seal(x_of(1, 0), u32(3) + b"\x05" + struct.pack(">H", 20) + RTP + u32(0x40000001) + b"\xff")
a4 = seal(x_of(1, 0), u32(4) + b"\x05" + struct.pack(">H", 20) + RTP + u32(0x40000002) + b"\x04\x01")
b1 = seal(x_of(0, 0), u32(0x40000001) + b"\x08" + u32(1000))
b2 = seal(x_of(0, 0), u32(2) + b"\xfe" + u32(0x40000002) + b"\xff")
out("conn_a1", a1); out("conn_a2", a2); out("conn_a3", a3); out("conn_a4", a4)
out("conn_b1", b1); out("conn_b2", b2)
CAND = b"candidate:1 1 udp 33554431 reflector-2-777.reflector 596 typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag abcd network-id 1 network-cost 10"
body = b"\x01" + string(CAND) + string(b"abcd") + string(b"0123456789abcdefghijklmn")
out("conn_sig1", seal(x_of(1, 1), u32(0x40000001) + b"\x01" + body[0:]))   # signalling, caller
out("conn_sig_body", body)
# VideoFormats from the peer in a signalling packet (callee side), parsed by C
vf = b"\x01" + string(b"VP8") + b"\x02" + string(b"k") + string(b"v") + string(b"x") + string(b"y") + b"\x03"
out("conn_vf_body", vf)
out("conn_sigpeer", seal(x_of(0, 1), u32(0x40000007) + b"\x02" + vf))

# ---- reflector
TAG16 = bytes(0xA0 + i for i in range(16))
RT_OWN, RT_PEER = 0x01020304, 0xDEADBEEF
own16 = TAG16[:12] + struct.pack("<I", RT_OWN)
out("refl_hello", own16 + b"\xff" * 12 + b"\xfe\xff\xff\xff" + struct.pack(">Q", 123))
for n in (0, 1, 5, 20):
    out("refl_wrap_%d" % n, TAG16[:12] + struct.pack("<II", RT_PEER, RT_OWN) + struct.pack(">I", n)
        + data(n, 9, 7) + b"\0" * (-n % 4))

# ---- STUN
def attr(t, v): return struct.pack(">HH", t, len(v)) + v + b"\0" * (-len(v) % 4)
def finish(typ, txid, attrs, key):
    def hdr(extra): return struct.pack(">HHI", typ, len(attrs) + extra, 0x2112A442) + txid
    mi = hmac.new(key, hdr(24) + attrs, hashlib.sha1).digest()
    attrs += attr(0x0008, mi)
    fp = zlib.crc32(hdr(8) + attrs) ^ 0x5354554E
    attrs += attr(0x8028, struct.pack(">I", fp))
    return hdr(0) + attrs
TX = bytes(range(0x30, 0x3C))
TB = bytes(range(1, 9))
for name, ctl, uc in (("stun_req_ctl", 1, 1), ("stun_req_cld", 0, 0)):
    a = attr(0x0006, b"abcd:wxyz") + attr(0x0024, u32(0x7E0000FF))
    a += attr(0x802A if ctl else 0x8029, TB) + (attr(0x0025, b"") if uc else b"")
    out(name, finish(0x0001, TX, a, b"0123456789abcdefghijklmn"))
ip, port = 0x5BA3C801, 54321
xa = b"\x00\x01" + struct.pack(">H", port ^ 0x2112) + struct.pack(">I", ip ^ 0x2112A442)
out("stun_ok", finish(0x0101, TX, attr(0x0020, xa), b"pwdpwdpwdpwdpwdpwdpwdp"))
out("stun_ok_sw", finish(0x0101, TX, attr(0x8022, b"Telegram ") + attr(0x0020, xa), b"k"))
# SDP
out("sdp", b"candidate:1 0 udp 33554431 reflector-3-4000000000.reflector 599 typ relay generation 0 ufrag Ab9z network-id 1 network-cost 10")

# ---- RTP (c277_rtp) : tx header for rnd6 = data(6,3,1), caller (ssrc 2), opus 60 ms SILK NB (TOC 0x18)
OPUS60 = bytes([0x18]) + data(40, 5, 3)
r6 = data(6, 3, 1)
seq0 = struct.unpack(">H", r6[0:2])[0]; ts0 = struct.unpack(">I", r6[2:6])[0]
rtp1 = struct.pack(">BBHII", 0x80, 111, seq0, ts0, 2) + OPUS60
rtp2 = struct.pack(">BBHII", 0x80, 111, (seq0 + 1) & 0xFFFF, (ts0 + 2880) & 0xFFFFFFFF, 2) + OPUS60
out("rtp_tx1", rtp1); out("rtp_tx2", rtp2)
# header with CSRC x2 + one-byte extension (0xBEDE, 2 words) + padding 3
ext = b"\xbe\xde" + struct.pack(">H", 2) + b"\x10\xaa\x00\x00\x21\x01\x02\x00"
out("rtp_rx_ext", struct.pack(">BBHII", 0x80 | 0x20 | 0x10 | 2, 0x80 | 111, 500, 123456, 1)
    + struct.pack(">II", 7, 8) + ext + OPUS60 + b"\0\0\x03")

# ---- ICE request produced by c277_ice (rnd = data(44,3,1); remote ufrag "wxyz", pwd 24 x 'p')
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
rnd = data(44, 3, 1)
lufrag = "".join(ALPHA[b & 63] for b in rnd[0:4]).encode()
lpwd = "".join(ALPHA[b & 63] for b in rnd[4:28]).encode()
out("ice_ufrag", lufrag); out("ice_pwd", lpwd)
txid = rnd[36:44] + struct.pack(">I", 1)
a = attr(0x0006, b"wxyz:" + lufrag) + attr(0x0024, u32(0x6EFFFFFF)) + attr(0x802A, rnd[28:36])
out("ice_req1", finish(0x0001, txid, a, b"p" * 24))
# the same, after a first response: USE-CANDIDATE added, txid counter 2
a2 = a + attr(0x0025, b"")
out("ice_req2_uc", finish(0x0001, rnd[36:44] + struct.pack(">I", 3), a2, b"p" * 24))
# a peer request to us (controlled peer: ICE-CONTROLLED not conflicting with our controlling role),
# and its expected response
txp = bytes(range(0x50, 0x5C))
peer_req = finish(0x0001, txp, attr(0x0006, lufrag + b":wxyz") + attr(0x0024, u32(1)) + attr(0x8029, TB), lpwd)
out("ice_peer_req", peer_req)
xa2 = b"\x00\x01" + struct.pack(">H", 596 ^ 0x2112) + struct.pack(">I", 0x5B6C1108 ^ 0x2112A442)
out("ice_peer_resp", finish(0x0101, txp, attr(0x0020, xa2), lpwd))
