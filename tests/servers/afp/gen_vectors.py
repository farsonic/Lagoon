#!/usr/bin/env python3
# Lagoon AFP tests - computes the canned DHX2 / DHCAST128 exchanges and the
# modexp values used by tests/t_afp_unit.c, with Python's own big integers
# and the "cryptography" package's CAST5 (an implementation independent of
# src/core/crypto). Prints C initialisers.
# SPDX-License-Identifier: GPL-2.0-only
import hashlib
from cryptography.hazmat.decrepit.ciphers.algorithms import CAST5
from cryptography.hazmat.primitives.ciphers import Cipher, modes

def cbc(key, iv, data, enc=True):
    c = Cipher(CAST5(key), modes.CBC(iv))
    o = c.encryptor() if enc else c.decryptor()
    return o.update(data) + o.finalize()

def be(n, l): return n.to_bytes(l, 'big')
def inc(b): return be((int.from_bytes(b, 'big') + 1) % (1 << 128), 16)
def hexs(b): return b.hex()

# RFC 2409 Oakley group 2 (1024-bit MODP prime)
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
G = 2
RA = int("c0ffee" + "11" * 29, 16)          # 256-bit client secret
RB = int("5eed" + "42" * 62, 16)            # server secret
L = 128
MB = pow(G, RB, P)
MA = pow(G, RA, P)
KS = pow(MB, RA, P)
assert KS == pow(MA, RB, P)
K = hashlib.md5(be(KS, L)).digest()
CN = bytes(range(0x11, 0x21))               # client nonce (as the test sets it)
SN = bytes(range(0xa0, 0xb0))               # server nonce
PW = b"lagoon-test-pw"
ID = 0x1234
reply1 = be(ID, 2) + be(G, 4) + be(L, 2) + be(P, L) + be(MB, L)
cont1 = be(MA, L) + cbc(K, b"LWallace", CN)
# what the server does with cont1: decrypt, +1, add its nonce
assert cbc(K, b"LWallace", cont1[L:], False) == CN
reply2 = be(ID + 1, 2) + cbc(K, b"CJalbert", inc(CN) + SN)
cont2 = cbc(K, b"LWallace", inc(SN) + PW + bytes(256 - len(PW)))
print("/* DHX2 */")
print('static const char dhx2_reply1_hex[] = "%s";' % hexs(reply1))
print('static const char dhx2_ra_hex[] = "%s";' % hexs(be(RA, 32)))
print('#define DHX2_MA_MD5 "%s"' % hashlib.md5(be(MA, L)).hexdigest())
print('#define DHX2_K "%s"' % hexs(K))
print('#define DHX2_CONT1_MD5 "%s"' % hashlib.md5(cont1).hexdigest())
print('static const char dhx2_reply2_hex[] = "%s";' % hexs(reply2))
print('#define DHX2_CONT2_MD5 "%s"' % hashlib.md5(cont2).hexdigest())

# DHCAST128: fixed p, g = 7, key = shared secret
P2 = 0xBA2873DFB06057D43F2024744CEEE75B
RA2 = int("9a" + "37" * 15, 16)
RB2 = int("4d" + "c3" * 15, 16)
MA2 = pow(7, RA2, P2)
MB2 = pow(7, RB2, P2)
K2 = be(pow(MB2, RA2, P2), 16)
SN2 = bytes(range(0x50, 0x60))
rep = be(0x0777, 2) + be(MB2, 16) + cbc(K2, b"CJalbert", SN2 + bytes(16))
cont = cbc(K2, b"LWallace", inc(SN2) + PW + bytes(64 - len(PW)))
print("/* DHCAST128 */")
print('static const char dhc_ra_hex[] = "%s";' % hexs(be(RA2, 16)))
print('#define DHC_MA "%s"' % hexs(be(MA2, 16)))
print('static const char dhc_reply_hex[] = "%s";' % hexs(rep))
print('#define DHC_K "%s"' % hexs(K2))
print('#define DHC_CONT_MD5 "%s"' % hashlib.md5(cont).hexdigest())

# plain modexp checks
print("/* modexp */")
E = int("ab" * 40, 16)
B = int("31415926535897932384626433832795028841971693993751" * 3)
print('static const char mx_base_hex[] = "%s";' % hexs(be(B, (B.bit_length() + 7) // 8)))
print('static const char mx_exp_hex[] = "%s";' % hexs(be(E, 40)))
print('#define MX_RESULT_MD5 "%s"' % hashlib.md5(be(pow(B, E, P), L)).hexdigest())
print('#define MX_RESULT_HEAD "%s"' % hexs(be(pow(B, E, P), L)[:16]))
M3 = (1 << 521) - 1                          # Mersenne prime, odd, not a multiple of 32 bits
r3 = pow(3, 10**40 + 7, M3)
print('static const char mx3_exp_hex[] = "%s";' % hexs(be(10**40 + 7, 17)))
print('#define MX3_RESULT "%s"' % hexs(be(r3, 66)))
# 3^5 mod 7 = 5 in a 1-byte modulus, 2^0 = 1

# CAST-128: RFC 2144 B.2 maintenance test cut to 10000 rounds, and CBC
def ecb(k, b):
    e = Cipher(CAST5(k), modes.ECB()).encryptor()
    return e.update(b) + e.finalize()
key = bytes.fromhex("0123456712345678234567893456789A")
a = bytearray(key); b = bytearray(key)
for i in range(10000):
    a[0:8] = ecb(bytes(b), bytes(a[0:8])); a[8:16] = ecb(bytes(b), bytes(a[8:16]))
    b[0:8] = ecb(bytes(a), bytes(b[0:8])); b[8:16] = ecb(bytes(a), bytes(b[8:16]))
print('#define T_CAST_A10K "%s"' % a.hex())
print('#define T_CAST_B10K "%s"' % b.hex())
print('#define T_CAST_CBC "%s"' % cbc(key, b"LWallace", b"0123456789abcdefFEDCBA98").hex())
