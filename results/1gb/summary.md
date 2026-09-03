# 1 GiB Vault Encryption Benchmark — results

Host: **viper-gateway-b** (Raspberry Pi 4 / BCM2711, Cortex-A72). n=5 per cell. Key SHA-256("viper5000")[:16].

| Phase | Cipher | Variant | Time (1 GiB) | Throughput |
|---|---|---|---|---|
| Bravo | ASCON-128 | in-memory (cipher only, no disk) | 9.14 s ±0.02 | **117.54 MB/s** ±0.23 |
| Bravo | ASCON-128 | 1 GiB file, warm (SD-bound) | 54.59 s ±0.18 | **19.67 MB/s** ±0.06 |
| Bravo | ASCON-128 | 1 GiB file, cold (SD-bound) | 75.25 s ±0.24 | **14.27 MB/s** ±0.05 |
| Charlie | AES-128-GCM | in-memory (cipher only, no disk) | 18.37 s ±0.01 | **58.45 MB/s** ±0.02 |
| Charlie | AES-128-GCM | 1 GiB file, warm (SD-bound) | 49.97 s ±8.82 | **22.43 MB/s** ±5.36 |
| Charlie | AES-128-GCM | 1 GiB file, cold (SD-bound) | 84.10 s ±1.23 | **12.77 MB/s** ±0.19 |

## Reading
- **`mem` = the cipher comparison.** No disk I/O: ASCON-128 **117.5 MB/s** vs AES-128-GCM **58.4 MB/s** — ASCON is **~2.0× faster**.
- Cause: the Pi 4 (BCM2711) has **no ARMv8-A AES instructions**, so OpenSSL runs AES-GCM in software; ASCON (LWC) is fast in plain software. On x86 with AES-NI the ranking flips (AES ≫ ASCON).
- `warm`/`cold` variants are **SD-bound** (~14–20 MB/s write ceiling) and do not reflect the cipher; kept in `warm/` and `cold/` for the end-to-end system cost only.
