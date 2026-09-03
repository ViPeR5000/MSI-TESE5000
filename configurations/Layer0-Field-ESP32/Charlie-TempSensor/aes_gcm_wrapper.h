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

    bool isReady() { return _ready; }

private:
    uint8_t _key[16] = {};
    bool _ready = false;
};
