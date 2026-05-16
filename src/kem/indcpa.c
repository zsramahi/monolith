/*
 * ind-cpa pke for monolith kem.
 * adapted from the public-domain crystals-kyber reference (cc0 / apache 2.0).
 */

#include <string.h>
#include "indcpa.h"
#include "poly.h"
#include "keccak.h"

static void packpk(uint8_t r[KEMINDCPAPUBKEYBYTES], polyvec *pk, const uint8_t seed[KEMSYMBYTES]) {
    pvtobytes(r, pk);
    memcpy(r + KEMPOLYVECBYTES, seed, KEMSYMBYTES);
}

static void unpackpk(polyvec *pk, uint8_t seed[KEMSYMBYTES], const uint8_t packed[KEMINDCPAPUBKEYBYTES]) {
    pvfrombytes(pk, packed);
    memcpy(seed, packed + KEMPOLYVECBYTES, KEMSYMBYTES);
}

static void packct(uint8_t r[KEMINDCPACTBYTES], polyvec *b, poly *v) {
    pvcompress(r, b);
    polycompress(r + KEMPOLYVECCOMPRESSEDBYTES, v);
}

static void unpackct(polyvec *b, poly *v, const uint8_t c[KEMINDCPACTBYTES]) {
    pvdecompress(b, c);
    polydecompress(v, c + KEMPOLYVECCOMPRESSEDBYTES);
}

static unsigned int rejuniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t v0 = (uint16_t)(((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF);
        uint16_t v1 = (uint16_t)(((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF);
        pos += 3;
        if (v0 < KEMQ) r[ctr++] = (int16_t)v0;
        if (ctr < len && v1 < KEMQ) r[ctr++] = (int16_t)v1;
    }
    return ctr;
}

#define GENMATRIXNBLOCKS ((12 * KEMN / 8 * (1 << 12) / KEMQ + SHAKE128RATE) / SHAKE128RATE)

static void genmatrix(polyvec *a, const uint8_t seed[KEMSYMBYTES], int transposed) {
    uint8_t buf[GENMATRIXNBLOCKS * SHAKE128RATE + 2];
    keccak st;
    for (unsigned int i = 0; i < KEMK; i++) {
        for (unsigned int j = 0; j < KEMK; j++) {
            uint8_t ext[KEMSYMBYTES + 2];
            memcpy(ext, seed, KEMSYMBYTES);
            if (transposed) {
                ext[KEMSYMBYTES + 0] = (uint8_t)i;
                ext[KEMSYMBYTES + 1] = (uint8_t)j;
            } else {
                ext[KEMSYMBYTES + 0] = (uint8_t)j;
                ext[KEMSYMBYTES + 1] = (uint8_t)i;
            }
            shake128init(&st);
            shake128absorbonce(&st, ext, sizeof(ext));
            shake128squeezeblocks(buf, GENMATRIXNBLOCKS, &st);
            unsigned int buflen = GENMATRIXNBLOCKS * SHAKE128RATE;
            unsigned int ctr = rejuniform(a[i].vec[j].coeffs, KEMN, buf, buflen);
            while (ctr < KEMN) {
                shake128squeezeblocks(buf, 1, &st);
                buflen = SHAKE128RATE;
                ctr += rejuniform(a[i].vec[j].coeffs + ctr, KEMN - ctr, buf, buflen);
            }
        }
    }
}

void indcpakeypair(uint8_t pk[KEMINDCPAPUBKEYBYTES],
                   uint8_t sk[KEMINDCPASECKEYBYTES],
                   const uint8_t coins[KEMSYMBYTES]) {
    uint8_t buf[2 * KEMSYMBYTES];
    uint8_t hashin[KEMSYMBYTES + 1];
    memcpy(hashin, coins, KEMSYMBYTES);
    hashin[KEMSYMBYTES] = (uint8_t)KEMK;
    sha3512(buf, hashin, KEMSYMBYTES + 1);

    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed  = buf + KEMSYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KEMK], e, pkpv, skpv;

    genmatrix(a, publicseed, 0);

    for (unsigned int i = 0; i < KEMK; i++) polynoiseeta1(&skpv.vec[i], noiseseed, nonce++);
    for (unsigned int i = 0; i < KEMK; i++) polynoiseeta1(&e.vec[i],   noiseseed, nonce++);

    pvntt(&skpv);
    pvntt(&e);

    for (unsigned int i = 0; i < KEMK; i++) {
        pvbasemulaccmont(&pkpv.vec[i], &a[i], &skpv);
        polytomont(&pkpv.vec[i]);
    }

    pvadd(&pkpv, &pkpv, &e);
    pvreduce(&pkpv);

    pvtobytes(sk, &skpv);
    packpk(pk, &pkpv, publicseed);
}

void indcpaenc(uint8_t c[KEMINDCPACTBYTES],
               const uint8_t m[KEMINDCPAMSGBYTES],
               const uint8_t pk[KEMINDCPAPUBKEYBYTES],
               const uint8_t coins[KEMSYMBYTES]) {
    uint8_t seed[KEMSYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KEMK], b;
    poly v, k, epp;

    unpackpk(&pkpv, seed, pk);
    polyfrommsg(&k, m);
    genmatrix(at, seed, 1);

    for (unsigned int i = 0; i < KEMK; i++) polynoiseeta1(&sp.vec[i], coins, nonce++);
    for (unsigned int i = 0; i < KEMK; i++) polynoiseeta2(&ep.vec[i], coins, nonce++);
    polynoiseeta2(&epp, coins, nonce++);

    pvntt(&sp);

    for (unsigned int i = 0; i < KEMK; i++)
        pvbasemulaccmont(&b.vec[i], &at[i], &sp);

    pvbasemulaccmont(&v, &pkpv, &sp);

    pvinvntttomont(&b);
    polyinvntttomont(&v);

    pvadd(&b, &b, &ep);
    polyadd(&v, &v, &epp);
    polyadd(&v, &v, &k);
    pvreduce(&b);
    polyreduce(&v);

    packct(c, &b, &v);
}

void indcpadec(uint8_t m[KEMINDCPAMSGBYTES],
               const uint8_t c[KEMINDCPACTBYTES],
               const uint8_t sk[KEMINDCPASECKEYBYTES]) {
    polyvec b, skpv;
    poly v, mp;

    unpackct(&b, &v, c);
    pvfrombytes(&skpv, sk);

    pvntt(&b);
    pvbasemulaccmont(&mp, &skpv, &b);
    polyinvntttomont(&mp);

    polysub(&mp, &v, &mp);
    polyreduce(&mp);

    polytomsg(m, &mp);
}
