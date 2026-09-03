#!/usr/bin/env python3
"""
aes_bench.py — streaming AES-128-GCM encryptor for the 1 GiB gateway benchmark
(Charlie phase). Same cipher/wire format as bridge_charlie.py:
wire = iv[12] | ciphertext | tag[16]. cryptography (OpenSSL, AES-NI/ARMv8 AES).

Run:  python3 aes_bench.py <key_hex_32> <infile> <outfile>
Emits one JSON metrics line to stdout. Time is end-to-end (read+encrypt+write+
fsync), 1 MiB chunks, streaming update()/finalize() — O(1) memory.
"""
import json, os, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 1 << 20  # 1 MiB


def _selftest():
    key = bytes.fromhex("393a58192a69b6483cc0ec89d27e30f6")
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ct = enc.update(b"viper5000" * 7) + enc.finalize()
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, enc.tag)).decryptor()
    assert dec.update(ct) + dec.finalize() == b"viper5000" * 7
    print("[aes_bench] self-test PASSED")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest(); return
    if len(sys.argv) != 4:
        sys.exit(f"usage: {sys.argv[0]} <key_hex_32> <in> <out>   (or --selftest)")
    key = bytes.fromhex(sys.argv[1])
    if len(key) != 16:
        sys.exit("key must be 16 bytes (32 hex chars) for AES-128-GCM")
    infile, outfile = sys.argv[2], sys.argv[3]
    iv = os.urandom(12)

    t0 = time.perf_counter()
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    in_bytes = 0
    with open(infile, "rb") as fi, open(outfile, "wb") as fo:
        fo.write(iv)                          # wire: iv first
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            in_bytes += len(chunk)
            fo.write(enc.update(chunk))
        fo.write(enc.finalize())
        fo.write(enc.tag)                     # 16-byte tag last
        fo.flush(); os.fsync(fo.fileno())     # count the SD write
    secs = time.perf_counter() - t0

    out_bytes = 12 + in_bytes + 16
    print(json.dumps({
        "algo": "AES-128-GCM",
        "time_s": round(secs, 3),
        "in_bytes": in_bytes,
        "out_bytes": out_bytes,
        "throughput_MBps": round((in_bytes / 1e6) / secs, 2),
        "iv": iv.hex(),
        "tag": enc.tag.hex(),
    }))


if __name__ == "__main__":
    main()
