// ECDH secp384r1 key exchange + HKDF-SHA256 session key derivation
// Uses mbedTLS built into ESP32 SDK — no extra library needed
// Protocol: ESP32 sends client_pub_b64 → server returns server_pub_b64
//           Both sides derive the same 16-byte AES-128 key via HKDF-SHA256
#pragma once
#include <Arduino.h>
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"

class EcdhKex {
public:
    EcdhKex() {
        mbedtls_ecp_group_init(&_grp);
        mbedtls_ecp_point_init(&_Q);
        mbedtls_ecp_point_init(&_Qp);
        mbedtls_mpi_init(&_d);
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_drbg);
        mbedtls_ctr_drbg_seed(&_drbg, mbedtls_entropy_func, &_entropy, nullptr, 0);
        mbedtls_ecp_group_load(&_grp, MBEDTLS_ECP_DP_SECP384R1);
    }

    ~EcdhKex() {
        mbedtls_ecp_group_free(&_grp);
        mbedtls_ecp_point_free(&_Q);
        mbedtls_ecp_point_free(&_Qp);
        mbedtls_mpi_free(&_d);
        mbedtls_entropy_free(&_entropy);
        mbedtls_ctr_drbg_free(&_drbg);
    }

    // Generate ephemeral key pair; returns base64-encoded uncompressed P-384 public key
    String genPublic() {
        if (mbedtls_ecdh_gen_public(&_grp, &_d, &_Q,
                mbedtls_ctr_drbg_random, &_drbg) != 0) return "";
        uint8_t buf[97];
        size_t len = 0;
        mbedtls_ecp_point_write_binary(&_grp, &_Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof(buf));
        char b64[200];
        size_t b64_len = 0;
        mbedtls_base64_encode((uint8_t*)b64, sizeof(b64), &b64_len, buf, len);
        return String(b64).substring(0, b64_len);
    }

    // Given server's b64 public key, compute ECDH then HKDF → 16-byte key
    bool deriveKey(const char* srv_b64, uint8_t* out16) {
        uint8_t srv_pub[97];
        size_t srv_len = 0;
        if (mbedtls_base64_decode(srv_pub, sizeof(srv_pub), &srv_len,
                (const uint8_t*)srv_b64, strlen(srv_b64)) != 0) return false;
        if (mbedtls_ecp_point_read_binary(&_grp, &_Qp, srv_pub, srv_len) != 0) return false;

        mbedtls_mpi z;
        mbedtls_mpi_init(&z);
        int ret = mbedtls_ecdh_compute_shared(&_grp, &z, &_Qp, &_d,
            mbedtls_ctr_drbg_random, &_drbg);
        if (ret != 0) { mbedtls_mpi_free(&z); return false; }

        uint8_t z_bytes[48] = {};
        mbedtls_mpi_write_binary(&z, z_bytes, 48);
        mbedtls_mpi_free(&z);

        // HKDF-SHA256 à mão (o core ESP32 não exporta mbedtls_hkdf). Só HMAC.
        // Deve bater byte-a-byte com o servidor: HKDF(salt=None, info="charlie-aes-key").
        // ponytail: info string must match server's HKDF call exactly
        return hkdf_sha256_expand16(z_bytes, 48, (const uint8_t*)"charlie-aes-key", 15, out16);
    }

private:
    mbedtls_ecp_group    _grp;
    mbedtls_ecp_point    _Q, _Qp;
    mbedtls_mpi          _d;
    mbedtls_entropy_context  _entropy;
    mbedtls_ctr_drbg_context _drbg;

    // HKDF-SHA256 com salt vazio (== salt de 32 zeros, igual a cryptography salt=None).
    // L=16 ≤ 32 ⇒ basta um bloco de expansão. Retorna false em erro.
    static bool hkdf_sha256_expand16(const uint8_t* ikm, size_t ikm_len,
                                     const uint8_t* info, size_t info_len,
                                     uint8_t* out16) {
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!md) return false;
        uint8_t zero_salt[32] = {0};
        uint8_t prk[32];
        // Extract: PRK = HMAC(salt=32×0x00, IKM)
        if (mbedtls_md_hmac(md, zero_salt, sizeof(zero_salt), ikm, ikm_len, prk) != 0) return false;
        // Expand: T(1) = HMAC(PRK, info || 0x01); OKM = T(1)[:16]
        uint8_t t_in[64];
        if (info_len > sizeof(t_in) - 1) return false;
        memcpy(t_in, info, info_len);
        t_in[info_len] = 0x01;
        uint8_t okm[32];
        if (mbedtls_md_hmac(md, prk, sizeof(prk), t_in, info_len + 1, okm) != 0) return false;
        memcpy(out16, okm, 16);
        return true;
    }
};
