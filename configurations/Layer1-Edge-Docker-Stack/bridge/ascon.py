"""
ASCON-128 Authenticated Encryption (NIST LWC Standard, FIPS 232)

Parameters: key=128-bit, nonce=128-bit, rate=64-bit, a=12, b=6, tag=128-bit
Wire format (shared with ESP32 firmware): Base64( nonce[16] | ciphertext | tag[16] )
"""

import os
import struct
import base64

_IV    = 0x80400c0600000000
_RC    = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
_M64   = 0xFFFFFFFFFFFFFFFF
RATE   = 8
KEY_LEN   = 16
NONCE_LEN = 16
TAG_LEN   = 16


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _M64


def _round(s: list, rc: int) -> None:
    s[2] ^= rc
    s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1]
    t = [
        (s[0] ^ (~s[1] & s[2])) & _M64,
        (s[1] ^ (~s[2] & s[3])) & _M64,
        (s[2] ^ (~s[3] & s[4])) & _M64,
        (s[3] ^ (~s[4] & s[0])) & _M64,
        (s[4] ^ (~s[0] & s[1])) & _M64,
    ]
    t[1] ^= t[0]; t[0] ^= t[4]; t[3] ^= t[2]; t[2] = (~t[2]) & _M64
    s[:] = [v & _M64 for v in t]
    s[0] ^= (_rotr(s[0],19) ^ _rotr(s[0],28)) & _M64
    s[1] ^= (_rotr(s[1],61) ^ _rotr(s[1],39)) & _M64
    s[2] ^= (_rotr(s[2], 1) ^ _rotr(s[2], 6)) & _M64
    s[3] ^= (_rotr(s[3],10) ^ _rotr(s[3],17)) & _M64
    s[4] ^= (_rotr(s[4], 7) ^ _rotr(s[4],41)) & _M64


def _perm(s: list, rounds: int) -> None:
    for r in range(12 - rounds, 12):
        _round(s, _RC[r])


def _w(b: bytes) -> int:       return struct.unpack('>Q', b)[0]
def _b(x: int)   -> bytes:     return struct.pack('>Q', x)
def _wpad(b: bytes, n: int) -> int:
    return _w(b + b'\x80' + b'\x00' * (7 - n))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes = b'') -> tuple:
    """Returns (ciphertext_bytes, tag_bytes).  len(ciphertext) == len(plaintext)."""
    assert len(key) == KEY_LEN and len(nonce) == NONCE_LEN, "key/nonce length mismatch"
    K0, K1 = _w(key[:8]), _w(key[8:])
    s = [_IV, K0, K1, _w(nonce[:8]), _w(nonce[8:])]
    _perm(s, 12)
    s[3] ^= K0; s[4] ^= K1

    if ad:
        i = 0
        while i + RATE <= len(ad):
            s[0] ^= _w(ad[i:i+RATE]); _perm(s, 6); i += RATE
        s[0] ^= _wpad(ad[i:], len(ad)-i); _perm(s, 6)
    s[4] ^= 1  # domain separation

    ct = b''; i = 0
    while i + RATE <= len(plaintext):
        s[0] ^= _w(plaintext[i:i+RATE]); ct += _b(s[0]); _perm(s, 6); i += RATE
    # final block is always processed (pure-pad block when plen % RATE == 0), no trailing perm
    last = len(plaintext) - i
    s[0] ^= _wpad(plaintext[i:], last)
    ct += _b(s[0])[:last]

    s[1] ^= K0; s[2] ^= K1; _perm(s, 12); s[3] ^= K0; s[4] ^= K1
    return ct, _b(s[3]) + _b(s[4])


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, ad: bytes = b''):
    """Returns plaintext bytes, or None if authentication tag does not match."""
    assert len(key) == KEY_LEN and len(nonce) == NONCE_LEN and len(tag) == TAG_LEN
    K0, K1 = _w(key[:8]), _w(key[8:])
    s = [_IV, K0, K1, _w(nonce[:8]), _w(nonce[8:])]
    _perm(s, 12)
    s[3] ^= K0; s[4] ^= K1

    if ad:
        i = 0
        while i + RATE <= len(ad):
            s[0] ^= _w(ad[i:i+RATE]); _perm(s, 6); i += RATE
        s[0] ^= _wpad(ad[i:], len(ad)-i); _perm(s, 6)
    s[4] ^= 1

    pt = b''; i = 0
    while i + RATE <= len(ciphertext):
        ci = _w(ciphertext[i:i+RATE]); pt += _b(s[0] ^ ci); s[0] = ci; _perm(s, 6); i += RATE
    # final block is always processed (pure-pad block when ct_len % RATE == 0), no trailing perm
    last = len(ciphertext) - i
    s0b  = _b(s[0])
    pt_tail = bytes(s0b[j] ^ ciphertext[i+j] for j in range(last))
    pt += pt_tail
    s[0] ^= _wpad(pt_tail, last)  # mirror encryption state update

    s[1] ^= K0; s[2] ^= K1; _perm(s, 12); s[3] ^= K0; s[4] ^= K1
    calc = _b(s[3]) + _b(s[4])
    return pt if calc == tag else None


# ── High-level helpers matching ESP32 wire format ──────────────────────────────

def encrypt_to_b64(key: bytes, plaintext: bytes, ad: bytes = b'') -> str:
    """Encrypt and return Base64(nonce[16] | ciphertext | tag[16])."""
    nonce      = os.urandom(NONCE_LEN)
    ct, tag    = encrypt(key[:KEY_LEN], nonce, plaintext, ad)
    return base64.b64encode(nonce + ct + tag).decode()


def decrypt_from_b64(key: bytes, b64_data: str, ad: bytes = b''):
    """Decrypt Base64(nonce[16] | ciphertext | tag[16]).  Returns bytes or None."""
    raw = base64.b64decode(b64_data)
    if len(raw) < NONCE_LEN + TAG_LEN:
        return None
    nonce = raw[:NONCE_LEN]
    tag   = raw[-TAG_LEN:]
    ct    = raw[NONCE_LEN:-TAG_LEN]
    return decrypt(key[:KEY_LEN], nonce, ct, tag, ad)


# ── Self-test (official ASCON-128 v1.2 KAT + round-trip + auth) ────────────────
def _selftest() -> None:
    key = nonce = bytes(range(16))
    # Official LWC KAT Count=1: empty PT/AD -> tag E355159F292911F794CB1432A0103A8A.
    # This is the alignment edge case (plen % rate == 0) — guards standard compliance.
    ct, tag = encrypt(key, nonce, b'')
    assert ct == b'' and tag == bytes.fromhex("E355159F292911F794CB1432A0103A8A"), \
        f"KAT mismatch: {tag.hex()}"
    # round-trip across block-boundary lengths (0,7,8,9,16 exercise final-pad handling)
    for n in (0, 1, 7, 8, 9, 16, 24, 32):
        pt = bytes(range(n))
        c, t = encrypt(key, nonce, pt)
        assert len(c) == n and decrypt(key, nonce, c, t) == pt, f"round-trip failed len={n}"
    assert decrypt(key, nonce, ct, b'\x00'*16) is None, "auth must fail on bad tag"
    print("[ASCON] Self-test PASSED (official KAT + round-trip + auth)")


if __name__ == "__main__":
    _selftest()
