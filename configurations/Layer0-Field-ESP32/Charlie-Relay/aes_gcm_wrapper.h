// AES-128-GCM AEAD — mbedTLS (hardware-accelerated on ESP32)
// Wire format: Base64( iv[12] | ciphertext | tag[16] )
#pragma once
#include <Arduino.h>
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include "esp_random.h"

class AesGcmWrapper {
public:
    bool setKey(const uint8_t* key, size_t len) {
        if (len < 16) return false;
        memcpy(_key, key, 16);
        _ready = true;
        return true;
    }

    String encrypt(const String& plaintext) {
        if (!_ready) return "";
        const uint8_t* pt = (const uint8_t*)plaintext.c_str();
        size_t pt_len = plaintext.length();

        uint8_t iv[12];
        esp_fill_random(iv, 12);

        uint8_t* ct = (uint8_t*)malloc(pt_len);
        uint8_t tag[16];

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, _key, 128);
        mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
            pt_len, iv, 12, nullptr, 0, pt, ct, 16, tag);
        mbedtls_gcm_free(&ctx);

        size_t wire_len = 12 + pt_len + 16;
        uint8_t* wire = (uint8_t*)malloc(wire_len);
        memcpy(wire, iv, 12);
        memcpy(wire + 12, ct, pt_len);
        memcpy(wire + 12 + pt_len, tag, 16);
        free(ct);

        size_t b64_max = ((wire_len + 2) / 3) * 4 + 1;
        char* b64 = (char*)malloc(b64_max);
        size_t b64_len = 0;
        mbedtls_base64_encode((uint8_t*)b64, b64_max, &b64_len, wire, wire_len);
        free(wire);

        String r = String(b64).substring(0, b64_len);
        free(b64);
        return r;
    }

    // Decifra Base64(iv[12]|ct|tag[16]). Devolve "" em falha de autenticação.
    String decrypt(const String& b64) {
        if (!_ready) return "";
        size_t raw_len = 0;
        mbedtls_base64_decode(nullptr, 0, &raw_len, (const uint8_t*)b64.c_str(), b64.length());
        if (raw_len < 28) return "";
        uint8_t* wire = (uint8_t*)malloc(raw_len);
        if (!wire) return "";
        size_t actual = 0;
        if (mbedtls_base64_decode(wire, raw_len, &actual, (const uint8_t*)b64.c_str(), b64.length()) != 0
            || actual < 28) { free(wire); return ""; }

        const uint8_t* iv  = wire;
        size_t ct_len      = actual - 12 - 16;
        const uint8_t* ct  = wire + 12;
        const uint8_t* tag = wire + 12 + ct_len;

        uint8_t* pt = (uint8_t*)malloc(ct_len + 1);
        if (!pt) { free(wire); return ""; }

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, _key, 128);
        if (rc == 0)
            rc = mbedtls_gcm_auth_decrypt(&ctx, ct_len, iv, 12, nullptr, 0, tag, 16, ct, pt);
        mbedtls_gcm_free(&ctx);

        pt[ct_len] = '\0';
        String r = (rc == 0) ? String((char*)pt) : String();
        free(pt); free(wire);
        return r;
    }

    bool isReady() { return _ready; }

private:
    uint8_t _key[16] = {};
    bool _ready = false;
};
