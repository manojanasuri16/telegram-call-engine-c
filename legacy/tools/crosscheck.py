#!/usr/bin/env python3
"""Independent implementation of the libtgvoip short-format MTProto2 datagram
(spec docs/CALL-PROTOCOL.md sec. 2) using only hashlib + cryptography AES-ECB
(IGE built by hand). Prints "<name> <hex datagram>" lines for fixed inputs;
test_callproto.c builds the same datagrams and compares byte for byte.

Fixed inputs (must match test_callproto.c):
  key[i] = (i*7+3) & 255, peer_tag[i] = 0xA0+i, padding byte j = 0xC0+j."""
import hashlib, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes((i * 7 + 3) & 255 for i in range(256))
TAG = bytes(0xA0 + i for i in range(16))


def sha(b):
    return hashlib.sha256(b).digest()


def kdf2(msg_key, x):
    sa = sha(msg_key + KEY[x:x + 36])
    sb = sha(KEY[40 + x:40 + x + 36] + msg_key)
    return sa[0:8] + sb[8:24] + sa[24:32], sb[0:8] + sa[8:24] + sb[24:32]


def ige_enc(data, key, iv):
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    y, x = iv[:16], iv[16:]
    out = b""
    for i in range(0, len(data), 16):
        p = data[i:i + 16]
        c = bytes(a ^ b for a, b in zip(ecb.update(bytes(a ^ b for a, b in zip(p, y))), x))
        out += c
        y, x = c, p
    return out


def datagram(is_outgoing, ptype, ack_seq, seq, mask, payload):
    pkt = struct.pack("<BIIIB", ptype, ack_seq, seq, mask, 0) + payload
    inner = struct.pack("<H", len(pkt)) + pkt
    pad_len = 16 - len(inner) % 16
    if pad_len < 16:
        pad_len += 16
    inner += bytes(0xC0 + j for j in range(pad_len))
    x = 0 if is_outgoing else 8
    msg_key = sha(KEY[88 + x:88 + x + 32] + inner)[8:24]
    k, iv = kdf2(msg_key, x)
    return TAG + msg_key + ige_enc(inner, k, iv)


init = struct.pack("<IIIBIBB", 9, 3, 0, 1, 0x4F505553, 0, 0)
sd = bytes([0x01, 40]) + struct.pack("<I", 120) + bytes(range(40))
print("A", datagram(1, 1, 0, 1, 0, init).hex())
print("B", datagram(0, 4, 1000, 77, 0xA0000000, sd).hex())
print("C", datagram(1, 6, 3, 5, 3, b"").hex())
