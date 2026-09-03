#ifndef ASCON_WRAPPER_H
#define ASCON_WRAPPER_H

/*
 * ASCON-128 Authenticated Encryption (NIST LWC Standard, FIPS 232)
 *
 * Wire format: Base64( nonce[16] | ciphertext[plaintext_len] | tag[16] )
 *
 * Parameters: key=128-bit, nonce=128-bit, rate=64-bit, a=12, b=6, tag=128-bit
 * IV = 0x80400c0600000000
 */

#include <Arduino.h>
#include <mbedtls/base64.h>
#include <esp_random.h>

#define ASCON_KEY_LEN   16
#define ASCON_NONCE_LEN 16
#define ASCON_TAG_LEN   16
#define ASCON_RATE       8
#define ASCON_A         12
#define ASCON_B          6

static const uint64_t _ASCON_IV = 0x80400c0600000000ULL;
static const uint8_t  _ASCON_RC[12] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b
};

static inline uint64_t _rotr64(uint64_t x, int n)  { return (x>>n)|(x<<(64-n)); }

static inline uint64_t _be64_load(const uint8_t *b) {
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|
           ((uint64_t)b[3]<<32)|((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|
           ((uint64_t)b[6]<<8)|(uint64_t)b[7];
}
static inline void _be64_store(uint8_t *b, uint64_t x) {
    b[0]=(x>>56)&0xFF; b[1]=(x>>48)&0xFF; b[2]=(x>>40)&0xFF; b[3]=(x>>32)&0xFF;
    b[4]=(x>>24)&0xFF; b[5]=(x>>16)&0xFF; b[6]=(x>> 8)&0xFF; b[7]=x&0xFF;
}
static inline uint64_t _be64_load_pad(const uint8_t *b, size_t n) {
    uint8_t tmp[8]={0}; memcpy(tmp,b,n); tmp[n]=0x80; return _be64_load(tmp);
}

struct _AsconState { uint64_t x[5]; };

static void _ascon_round(_AsconState &s, uint8_t rc) {
    s.x[2] ^= rc;
    s.x[0]^=s.x[4]; s.x[4]^=s.x[3]; s.x[2]^=s.x[1];
    uint64_t t[5];
    t[0]=s.x[0]^(~s.x[1]&s.x[2]);
    t[1]=s.x[1]^(~s.x[2]&s.x[3]);
    t[2]=s.x[2]^(~s.x[3]&s.x[4]);
    t[3]=s.x[3]^(~s.x[4]&s.x[0]);
    t[4]=s.x[4]^(~s.x[0]&s.x[1]);
    t[1]^=t[0]; t[0]^=t[4]; t[3]^=t[2]; t[2]=~t[2];
    s.x[0]=t[0]; s.x[1]=t[1]; s.x[2]=t[2]; s.x[3]=t[3]; s.x[4]=t[4];
    s.x[0]^=_rotr64(s.x[0],19)^_rotr64(s.x[0],28);
    s.x[1]^=_rotr64(s.x[1],61)^_rotr64(s.x[1],39);
    s.x[2]^=_rotr64(s.x[2], 1)^_rotr64(s.x[2], 6);
    s.x[3]^=_rotr64(s.x[3],10)^_rotr64(s.x[3],17);
    s.x[4]^=_rotr64(s.x[4], 7)^_rotr64(s.x[4],41);
}
static void _ascon_perm(_AsconState &s, int rounds) {
    for (int r=12-rounds; r<12; r++) _ascon_round(s, _ASCON_RC[r]);
}

class Ascon128Wrapper {
public:
    Ascon128Wrapper() { memset(_key, 0, ASCON_KEY_LEN); }

    void setKey(const uint8_t *k, size_t len) {
        memset(_key, 0, ASCON_KEY_LEN);
        memcpy(_key, k, (len<ASCON_KEY_LEN)?len:ASCON_KEY_LEN);
    }

    /* Returns Base64(nonce[16] | ciphertext | tag[16]) */
    String encrypt(const String &plaintext) {
        const uint8_t *pt = (const uint8_t*)plaintext.c_str();
        size_t plen = plaintext.length();

        uint8_t nonce[ASCON_NONCE_LEN];
        esp_fill_random(nonce, ASCON_NONCE_LEN);

        size_t raw_len = ASCON_NONCE_LEN + plen + ASCON_TAG_LEN;
        uint8_t *raw = (uint8_t*)malloc(raw_len);
        if (!raw) return String();
        memcpy(raw, nonce, ASCON_NONCE_LEN);
        _enc_core(_key, nonce, pt, plen, raw+ASCON_NONCE_LEN, raw+ASCON_NONCE_LEN+plen);

        size_t b64_need=0;
        mbedtls_base64_encode(nullptr,0,&b64_need,raw,raw_len);
        uint8_t *b64=(uint8_t*)malloc(b64_need+1);
        if (!b64){free(raw);return String();}
        mbedtls_base64_encode(b64,b64_need,&b64_need,raw,raw_len);
        b64[b64_need]='\0';
        String r((char*)b64);
        free(b64); free(raw);
        return r;
    }

    /* Input: Base64(nonce[16] | ciphertext | tag[16]).  Returns "" on auth failure. */
    String decrypt(const String &b64_cipher) {
        const uint8_t *b64=(const uint8_t*)b64_cipher.c_str();
        size_t b64_len=b64_cipher.length(), raw_len=0;
        mbedtls_base64_decode(nullptr,0,&raw_len,b64,b64_len);
        if (raw_len < ASCON_NONCE_LEN+ASCON_TAG_LEN) return String();
        uint8_t *raw=(uint8_t*)malloc(raw_len);
        if (!raw) return String();
        size_t actual=0;
        if (mbedtls_base64_decode(raw,raw_len,&actual,b64,b64_len)!=0){free(raw);return String();}
        if (actual<ASCON_NONCE_LEN+ASCON_TAG_LEN){free(raw);return String();}

        const uint8_t *nonce=raw;
        size_t ct_len=actual-ASCON_NONCE_LEN-ASCON_TAG_LEN;
        const uint8_t *ct=raw+ASCON_NONCE_LEN;
        const uint8_t *tag=raw+ASCON_NONCE_LEN+ct_len;

        uint8_t *pt=(uint8_t*)malloc(ct_len+1);
        if (!pt){free(raw);return String();}
        bool ok=_dec_core(_key,nonce,ct,ct_len,tag,pt);
        pt[ct_len]='\0';
        String r=ok?String((char*)pt):String();
        free(pt); free(raw);
        return r;
    }

private:
    uint8_t _key[ASCON_KEY_LEN];

    void _enc_core(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *pt, size_t plen, uint8_t *ct, uint8_t *tag) {
        _AsconState s;
        uint64_t K0=_be64_load(key), K1=_be64_load(key+8);
        s.x[0]=_ASCON_IV; s.x[1]=K0; s.x[2]=K1;
        s.x[3]=_be64_load(nonce); s.x[4]=_be64_load(nonce+8);
        _ascon_perm(s,ASCON_A);
        s.x[3]^=K0; s.x[4]^=K1;
        /* domain separation (empty AD) */
        s.x[4]^=1ULL;
        size_t i=0;
        for(;i+ASCON_RATE<=plen;i+=ASCON_RATE){
            s.x[0]^=_be64_load(pt+i); _be64_store(ct+i,s.x[0]); _ascon_perm(s,ASCON_B);
        }
        /* final block always processed (pure-pad block when plen % RATE == 0), no trailing perm */
        {
            size_t last=plen-i;
            s.x[0]^=_be64_load_pad(pt+i,last);
            uint8_t tmp[8]; _be64_store(tmp,s.x[0]); memcpy(ct+i,tmp,last);
        }
        s.x[1]^=K0; s.x[2]^=K1; _ascon_perm(s,ASCON_A); s.x[3]^=K0; s.x[4]^=K1;
        _be64_store(tag,s.x[3]); _be64_store(tag+8,s.x[4]);
    }

    bool _dec_core(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *ct, size_t ct_len, const uint8_t *tag, uint8_t *pt) {
        _AsconState s;
        uint64_t K0=_be64_load(key), K1=_be64_load(key+8);
        s.x[0]=_ASCON_IV; s.x[1]=K0; s.x[2]=K1;
        s.x[3]=_be64_load(nonce); s.x[4]=_be64_load(nonce+8);
        _ascon_perm(s,ASCON_A);
        s.x[3]^=K0; s.x[4]^=K1;
        s.x[4]^=1ULL;
        size_t i=0;
        for(;i+ASCON_RATE<=ct_len;i+=ASCON_RATE){
            uint64_t ci=_be64_load(ct+i); _be64_store(pt+i,s.x[0]^ci);
            s.x[0]=ci; _ascon_perm(s,ASCON_B);
        }
        /* final block always processed (pure-pad block when ct_len % RATE == 0), no trailing perm */
        {
            size_t last=ct_len-i;
            uint8_t sx0[8]; _be64_store(sx0,s.x[0]);
            for(size_t j=0;j<last;j++) pt[i+j]=sx0[j]^ct[i+j];
            uint8_t pt_pad[8]={0}; memcpy(pt_pad,pt+i,last); pt_pad[last]=0x80;
            s.x[0]^=_be64_load(pt_pad);
        }
        s.x[1]^=K0; s.x[2]^=K1; _ascon_perm(s,ASCON_A); s.x[3]^=K0; s.x[4]^=K1;
        uint8_t ctag[ASCON_TAG_LEN];
        _be64_store(ctag,s.x[3]); _be64_store(ctag+8,s.x[4]);
        uint8_t diff=0;
        for(int j=0;j<ASCON_TAG_LEN;j++) diff|=ctag[j]^tag[j];
        return diff==0;
    }
};

#endif // ASCON_WRAPPER_H
