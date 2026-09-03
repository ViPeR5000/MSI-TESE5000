/*
 * aes_bench.c — streaming AES-128-GCM encryptor for the 1 GiB gateway benchmark
 * (Charlie phase), via OpenSSL EVP (uses ARMv8-A / AES-NI hardware AES).
 * Same wire format as bridge_charlie.py: iv[12] | ciphertext | tag[16].
 * Written in C so it is a same-language, same-I/O comparison against ascon_bench.c
 * (the original benchmark ran AES in Python, which masked the AES-NI advantage).
 *
 * Build:  gcc -O2 -o aes_bench aes_bench.c -lcrypto
 * Run:    ./aes_bench <key_hex_32> <infile> <outfile>
 * Emits one JSON metrics line. Time is end-to-end (read+encrypt+write+flush),
 * 1 MiB buffers, O(1) memory. No fsync — writes go to the page cache like the
 * original run, so this measures the cipher, not the SD card.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>

#ifndef CHUNK
#define CHUNK (1u<<20)   /* 1 MiB */
#endif
#define IVLEN  12
#define TAGLEN 16

static int hex2bin(const char*h,uint8_t*out,int n){
    for(int i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;out[i]=(uint8_t)v;}
    return 0;
}

int main(int argc,char**argv){
    if(argc!=4){fprintf(stderr,"usage: %s <key_hex_32> <in> <out>\n",argv[0]);return 2;}
    if(strlen(argv[1])!=32){fprintf(stderr,"key must be 32 hex chars (16 bytes)\n");return 2;}
    uint8_t key[16],iv[IVLEN],tag[TAGLEN];
    if(hex2bin(argv[1],key,16)){fprintf(stderr,"bad key hex\n");return 2;}

    /* ── in-memory throughput mode: ./aes_bench <key> --mem <total_bytes> ──
       Encrypts a 16 MiB RAM buffer repeatedly, output discarded. No file I/O,
       so this measures the cipher (ARMv8-A AES) on the CPU, not the SD card. */
    if(strcmp(argv[2],"--mem")==0){
        size_t total=strtoull(argv[3],NULL,10);
        size_t bufsz=16u<<20; total-=total%bufsz; if(total==0)total=bufsz;
        uint8_t *buf=malloc(bufsz), *ob=malloc(bufsz+16);
        if(!buf||!ob){fprintf(stderr,"oom\n");return 1;}
        for(size_t i=0;i<bufsz;i++) buf[i]=(uint8_t)(i*13+5);
        FILE*u=fopen("/dev/urandom","rb"); if(u){if(fread(iv,1,IVLEN,u)!=IVLEN){}fclose(u);}
        EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new(); int outl;
        struct timespec m0,m1; clock_gettime(CLOCK_MONOTONIC,&m0);
        EVP_EncryptInit_ex(ctx,EVP_aes_128_gcm(),NULL,NULL,NULL);
        EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,IVLEN,NULL);
        EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv);
        size_t done=0;
        while(done<total){EVP_EncryptUpdate(ctx,ob,&outl,buf,(int)bufsz);done+=bufsz;}
        EVP_EncryptFinal_ex(ctx,ob,&outl);
        EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,TAGLEN,tag);
        clock_gettime(CLOCK_MONOTONIC,&m1);
        EVP_CIPHER_CTX_free(ctx);
        double secs=(m1.tv_sec-m0.tv_sec)+(m1.tv_nsec-m0.tv_nsec)/1e9;
        printf("{\"algo\":\"AES-128-GCM\",\"time_s\":%.3f,\"in_bytes\":%zu,\"out_bytes\":%zu,"
               "\"throughput_MBps\":%.2f}\n",secs,total,total,(total/1e6)/secs);
        free(buf);free(ob);
        return 0;
    }

    FILE*u=fopen("/dev/urandom","rb");
    if(!u||fread(iv,1,IVLEN,u)!=IVLEN){fprintf(stderr,"iv read failed\n");return 1;}
    fclose(u);

    FILE*fi=fopen(argv[2],"rb"), *fo=fopen(argv[3],"wb");
    if(!fi||!fo){fprintf(stderr,"open failed\n");return 1;}

    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();
    if(!ctx){fprintf(stderr,"ctx alloc\n");return 1;}
    uint8_t *ibuf=malloc(CHUNK), *obuf=malloc(CHUNK+16);
    if(!ibuf||!obuf){fprintf(stderr,"oom\n");return 1;}

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);

    if(EVP_EncryptInit_ex(ctx,EVP_aes_128_gcm(),NULL,NULL,NULL)!=1
     ||EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,IVLEN,NULL)!=1
     ||EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv)!=1){fprintf(stderr,"init\n");return 1;}

    fwrite(iv,1,IVLEN,fo);                 /* wire: iv first */

    size_t in_bytes=0, n; int outl;
    while((n=fread(ibuf,1,CHUNK,fi))>0){
        in_bytes+=n;
        if(EVP_EncryptUpdate(ctx,obuf,&outl,ibuf,(int)n)!=1){fprintf(stderr,"update\n");return 1;}
        if(outl) fwrite(obuf,1,outl,fo);
    }
    if(EVP_EncryptFinal_ex(ctx,obuf,&outl)!=1){fprintf(stderr,"final\n");return 1;}
    if(outl) fwrite(obuf,1,outl,fo);       /* GCM: 0 */
    if(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,TAGLEN,tag)!=1){fprintf(stderr,"gettag\n");return 1;}
    fwrite(tag,1,TAGLEN,fo);               /* 16-byte tag last */
    fflush(fo);                            /* buffered write (no fsync): measure cipher, not SD */
    fclose(fo); fclose(fi);
    EVP_CIPHER_CTX_free(ctx);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double secs=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    size_t out_bytes=IVLEN+in_bytes+TAGLEN;
    double mbps=(in_bytes/1e6)/secs;

    char ivhex[2*IVLEN+1],thex[2*TAGLEN+1];
    for(int i=0;i<IVLEN;i++)  sprintf(ivhex+2*i,"%02x",iv[i]);
    for(int i=0;i<TAGLEN;i++) sprintf(thex+2*i,"%02x",tag[i]);
    printf("{\"algo\":\"AES-128-GCM\",\"time_s\":%.3f,\"in_bytes\":%zu,\"out_bytes\":%zu,"
           "\"throughput_MBps\":%.2f,\"iv\":\"%s\",\"tag\":\"%s\"}\n",
           secs,in_bytes,out_bytes,mbps,ivhex,thex);
    free(ibuf);free(obuf);
    return 0;
}
