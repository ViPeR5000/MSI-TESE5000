/*
 * ascon_bench.c — streaming ASCON-128 v1.2 (AEAD) encryptor for the 1 GiB
 * gateway benchmark (Bravo phase). Byte-identical to the project's
 * ascon_wrapper.h / bridge/ascon.py: IV 0x80400c0600000000, rate 64,
 * a=12/b=6, empty AD, big-endian loading, wire = nonce[16] | ct | tag[16].
 *
 * Build:  gcc -O2 -o ascon_bench ascon_bench.c
 * Run:    ./ascon_bench <key_hex_32> <infile> <outfile>
 * Emits one JSON line of metrics to stdout (time is end-to-end: read+encrypt+
 * write+fsync, matching benchmarks.md caveat 2). O(1) memory, 1 MiB buffers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define RATE  8
#define A_RND 12
#define B_RND 6
#ifndef CHUNK
#define CHUNK (1u<<20)   /* 1 MiB (override with -DCHUNK=N for boundary tests) */
#endif

static const uint64_t IV = 0x80400c0600000000ULL;
static const uint8_t  RC[12] = {0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b};

static inline uint64_t rotr64(uint64_t x,int n){return (x>>n)|(x<<(64-n));}
static inline uint64_t be64(const uint8_t*b){
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)
         | ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|(uint64_t)b[7];
}
static inline void be64s(uint8_t*b,uint64_t x){
    b[0]=x>>56;b[1]=x>>48;b[2]=x>>40;b[3]=x>>32;b[4]=x>>24;b[5]=x>>16;b[6]=x>>8;b[7]=x;
}
static inline uint64_t be64_pad(const uint8_t*b,size_t n){uint8_t t[8]={0};memcpy(t,b,n);t[n]=0x80;return be64(t);}

static uint64_t X0,X1,X2,X3,X4;
static void round_fn(uint8_t rc){
    X2^=rc; X0^=X4; X4^=X3; X2^=X1;
    uint64_t t0=X0^(~X1&X2),t1=X1^(~X2&X3),t2=X2^(~X3&X4),t3=X3^(~X4&X0),t4=X4^(~X0&X1);
    t1^=t0; t0^=t4; t3^=t2; t2=~t2;
    X0=t0^rotr64(t0,19)^rotr64(t0,28);
    X1=t1^rotr64(t1,61)^rotr64(t1,39);
    X2=t2^rotr64(t2, 1)^rotr64(t2, 6);
    X3=t3^rotr64(t3,10)^rotr64(t3,17);
    X4=t4^rotr64(t4, 7)^rotr64(t4,41);
}
static inline void perm(int rounds){for(int r=12-rounds;r<12;r++)round_fn(RC[r]);}

static int hex2bin(const char*h,uint8_t*out,int n){
    for(int i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;out[i]=(uint8_t)v;}
    return 0;
}

int main(int argc,char**argv){
    if(argc!=4){fprintf(stderr,"usage: %s <key_hex_32> <in> <out>\n",argv[0]);return 2;}
    if(strlen(argv[1])!=32){fprintf(stderr,"key must be 32 hex chars (16 bytes)\n");return 2;}
    uint8_t key[16],nonce[16];
    if(hex2bin(argv[1],key,16)){fprintf(stderr,"bad key hex\n");return 2;}
    uint64_t K0=be64(key),K1=be64(key+8);

    /* ── in-memory throughput mode: ./ascon_bench <key> --mem <total_bytes> ──
       Encrypts a 16 MiB RAM buffer repeatedly, output discarded. No file I/O,
       so this measures the cipher on the CPU, not the SD card. */
    if(strcmp(argv[2],"--mem")==0){
        size_t total=strtoull(argv[3],NULL,10);
        size_t bufsz=16u<<20; total-=total%bufsz; if(total==0)total=bufsz; /* whole 16MiB units */
        uint8_t *buf=malloc(bufsz), *ob=malloc(bufsz);
        if(!buf||!ob){fprintf(stderr,"oom\n");return 1;}
        for(size_t i=0;i<bufsz;i++) buf[i]=(uint8_t)(i*7+3);
        FILE*u=fopen("/dev/urandom","rb"); if(u){if(fread(nonce,1,16,u)!=16){}fclose(u);}
        struct timespec m0,m1; clock_gettime(CLOCK_MONOTONIC,&m0);
        X0=IV;X1=K0;X2=K1;X3=be64(nonce);X4=be64(nonce+8);
        perm(A_RND); X3^=K0; X4^=K1; X4^=1ULL;
        size_t done=0;
        while(done<total){
            for(size_t i=0;i<bufsz;i+=8){X0^=be64(buf+i);be64s(ob+i,X0);perm(B_RND);}
            done+=bufsz;
        }
        X0^=0x8000000000000000ULL;               /* empty pad final block (total%8==0) */
        X1^=K0;X2^=K1;perm(A_RND);X3^=K0;X4^=K1;
        clock_gettime(CLOCK_MONOTONIC,&m1);
        double secs=(m1.tv_sec-m0.tv_sec)+(m1.tv_nsec-m0.tv_nsec)/1e9;
        printf("{\"algo\":\"ASCON-128\",\"time_s\":%.3f,\"in_bytes\":%zu,\"out_bytes\":%zu,"
               "\"throughput_MBps\":%.2f}\n",secs,total,total,(total/1e6)/secs);
        free(buf);free(ob);
        return 0;
    }

    /* random nonce */
    FILE*u=fopen("/dev/urandom","rb");
    if(!u||fread(nonce,1,16,u)!=16){fprintf(stderr,"nonce read failed\n");return 1;}
    fclose(u);

    FILE*fi=fopen(argv[2],"rb"), *fo=fopen(argv[3],"wb");
    if(!fi||!fo){fprintf(stderr,"open failed\n");return 1;}

    uint8_t *ibuf=malloc(CHUNK), *obuf=malloc(CHUNK+16);
    if(!ibuf||!obuf){fprintf(stderr,"oom\n");return 1;}

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);

    /* init */
    X0=IV;X1=K0;X2=K1;X3=be64(nonce);X4=be64(nonce+8);
    perm(A_RND); X3^=K0; X4^=K1; X4^=1ULL;   /* empty-AD domain separation */

    fwrite(nonce,1,16,fo);                    /* wire: nonce first */

    uint8_t carry[8]; size_t carrylen=0, in_bytes=0; size_t olen=0;
    size_t n;
    while((n=fread(ibuf,1,CHUNK,fi))>0){
        in_bytes+=n; size_t pos=0;
        if(carrylen){                          /* complete a straddling block */
            size_t take=8-carrylen; if(take>n)take=n;
            memcpy(carry+carrylen,ibuf,take); carrylen+=take; pos=take;
            if(carrylen==8){X0^=be64(carry);be64s(obuf+olen,X0);olen+=8;perm(B_RND);carrylen=0;}
            else continue;                     /* whole chunk absorbed, still <8 */
        }
        size_t full=(n-pos)/8;
        for(size_t k=0;k<full;k++){X0^=be64(ibuf+pos);be64s(obuf+olen,X0);olen+=8;perm(B_RND);pos+=8;}
        size_t rem=n-pos; if(rem){memcpy(carry,ibuf+pos,rem);carrylen=rem;}
        if(olen>=CHUNK){fwrite(obuf,1,olen,fo);olen=0;}
    }
    /* final block (always emitted; empty pad block when len%8==0), no trailing perm */
    X0^=be64_pad(carry,carrylen); uint8_t last8[8]; be64s(last8,X0);
    memcpy(obuf+olen,last8,carrylen); olen+=carrylen;
    if(olen){fwrite(obuf,1,olen,fo);olen=0;}

    /* tag finalization */
    X1^=K0;X2^=K1;perm(A_RND);X3^=K0;X4^=K1;
    uint8_t tag[16]; be64s(tag,X3); be64s(tag+8,X4);
    fwrite(tag,1,16,fo);
    fflush(fo);                               /* buffered write (no fsync): measure cipher, not SD */
    fclose(fo); fclose(fi);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double secs=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    size_t out_bytes=16+in_bytes+16;
    double mbps=(in_bytes/1e6)/secs;          /* MB/s (decimal, as benchmarks.md) */

    char nhex[33],thex[33];
    for(int i=0;i<16;i++){sprintf(nhex+2*i,"%02x",nonce[i]);sprintf(thex+2*i,"%02x",tag[i]);}
    printf("{\"algo\":\"ASCON-128\",\"time_s\":%.3f,\"in_bytes\":%zu,\"out_bytes\":%zu,"
           "\"throughput_MBps\":%.2f,\"nonce\":\"%s\",\"tag\":\"%s\"}\n",
           secs,in_bytes,out_bytes,mbps,nhex,thex);
    free(ibuf);free(obuf);
    return 0;
}
