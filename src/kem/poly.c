/*
 * polynomial arithmetic for monolith kem.
 * adapted from the public-domain crystals-kyber reference (cc0 / apache 2.0).
 */

#include <string.h>
#include "poly.h"
#include "reduce.h"
#include "keccak.h"

const int16_t zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

static int16_t fqmul(int16_t a, int16_t b) {
    return montred((int32_t)a * b);
}

void ntt(int16_t r[256]) {
    unsigned int k = 1;
    for (unsigned int len = 128; len >= 2; len >>= 1) {
        for (unsigned int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (unsigned int j = start; j < start + len; j++) {
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = (int16_t)(r[j] - t);
                r[j] = (int16_t)(r[j] + t);
            }
        }
    }
}

void invntt(int16_t r[256]) {
    const int16_t f = 1441;
    unsigned int k = 127;
    for (unsigned int len = 2; len <= 128; len <<= 1) {
        for (unsigned int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas[k--];
            for (unsigned int j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrettred((int16_t)(t + r[j + len]));
                r[j + len] = (int16_t)(r[j + len] - t);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }
    for (unsigned int j = 0; j < 256; j++) r[j] = fqmul(r[j], f);
}

void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] = (int16_t)(r[0] + fqmul(a[0], b[0]));
    r[1]  = fqmul(a[0], b[1]);
    r[1] = (int16_t)(r[1] + fqmul(a[1], b[0]));
}

static uint32_t load32le(const uint8_t x[4]) {
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8)
         | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

static void cbd2(poly *r, const uint8_t buf[2 * KEMN / 4]) {
    for (unsigned int i = 0; i < KEMN / 8; i++) {
        uint32_t t = load32le(buf + 4 * i);
        uint32_t d = t & 0x55555555U;
        d += (t >> 1) & 0x55555555U;
        for (unsigned int j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >> (4 * j + 0)) & 0x3);
            int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3);
            r->coeffs[8 * i + j] = (int16_t)(a - b);
        }
    }
}

void polycompress(uint8_t r[KEMPOLYCOMPRESSEDBYTES], const poly *a) {
    uint8_t t[8];
    for (unsigned int i = 0; i < KEMN / 8; i++) {
        for (unsigned int j = 0; j < 8; j++) {
            int16_t u = a->coeffs[8 * i + j];
            u = (int16_t)(u + ((u >> 15) & KEMQ));
            uint32_t d0 = (uint32_t)u << 5;
            d0 += 1664;
            d0 *= 40318;
            d0 >>= 27;
            t[j] = (uint8_t)(d0 & 0x1f);
        }
        r[0] = (uint8_t)((t[0] >> 0) | (t[1] << 5));
        r[1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
        r[2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
        r[3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
        r[4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
        r += 5;
    }
}

void polydecompress(poly *r, const uint8_t a[KEMPOLYCOMPRESSEDBYTES]) {
    uint8_t t[8];
    for (unsigned int i = 0; i < KEMN / 8; i++) {
        t[0] = (uint8_t)(a[0] >> 0);
        t[1] = (uint8_t)((a[0] >> 5) | (a[1] << 3));
        t[2] = (uint8_t)(a[1] >> 2);
        t[3] = (uint8_t)((a[1] >> 7) | (a[2] << 1));
        t[4] = (uint8_t)((a[2] >> 4) | (a[3] << 4));
        t[5] = (uint8_t)(a[3] >> 1);
        t[6] = (uint8_t)((a[3] >> 6) | (a[4] << 2));
        t[7] = (uint8_t)(a[4] >> 3);
        a += 5;
        for (unsigned int j = 0; j < 8; j++)
            r->coeffs[8 * i + j] = (int16_t)(((uint32_t)(t[j] & 31) * KEMQ + 16) >> 5);
    }
}

void polytobytes(uint8_t r[KEMPOLYBYTES], const poly *a) {
    for (unsigned int i = 0; i < KEMN / 2; i++) {
        uint16_t t0 = (uint16_t)a->coeffs[2 * i];
        t0 = (uint16_t)(t0 + (((int16_t)t0 >> 15) & KEMQ));
        uint16_t t1 = (uint16_t)a->coeffs[2 * i + 1];
        t1 = (uint16_t)(t1 + (((int16_t)t1 >> 15) & KEMQ));
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void polyfrombytes(poly *r, const uint8_t a[KEMPOLYBYTES]) {
    for (unsigned int i = 0; i < KEMN / 2; i++) {
        r->coeffs[2 * i]     = (int16_t)(((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF);
        r->coeffs[2 * i + 1] = (int16_t)(((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF);
    }
}

void polyfrommsg(poly *r, const uint8_t msg[KEMINDCPAMSGBYTES]) {
    for (unsigned int i = 0; i < KEMN / 8; i++) {
        for (unsigned int j = 0; j < 8; j++) {
            int16_t mask = (int16_t)(-((int16_t)((msg[i] >> j) & 1)));
            r->coeffs[8 * i + j] = (int16_t)(mask & ((KEMQ + 1) / 2));
        }
    }
}

void polytomsg(uint8_t msg[KEMINDCPAMSGBYTES], const poly *a) {
    for (unsigned int i = 0; i < KEMN / 8; i++) {
        msg[i] = 0;
        for (unsigned int j = 0; j < 8; j++) {
            uint32_t t = (uint32_t)a->coeffs[8 * i + j];
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

static void prf(uint8_t *out, size_t outlen, const uint8_t key[KEMSYMBYTES], uint8_t nonce) {
    uint8_t ext[KEMSYMBYTES + 1];
    memcpy(ext, key, KEMSYMBYTES);
    ext[KEMSYMBYTES] = nonce;
    shake256(out, outlen, ext, sizeof(ext));
}

void polynoiseeta1(poly *r, const uint8_t seed[KEMSYMBYTES], uint8_t nonce) {
    uint8_t buf[KEMETA1 * KEMN / 4];
    prf(buf, sizeof(buf), seed, nonce);
    cbd2(r, buf);
}

void polynoiseeta2(poly *r, const uint8_t seed[KEMSYMBYTES], uint8_t nonce) {
    uint8_t buf[KEMETA2 * KEMN / 4];
    prf(buf, sizeof(buf), seed, nonce);
    cbd2(r, buf);
}

void polyntt(poly *r) {
    ntt(r->coeffs);
    polyreduce(r);
}

void polyinvntttomont(poly *r) {
    invntt(r->coeffs);
}

void polybasemulmont(poly *r, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < KEMN / 4; i++) {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], (int16_t)-zetas[64 + i]);
    }
}

void polytomont(poly *r) {
    const int16_t f = (int16_t)((1ULL << 32) % KEMQ);
    for (unsigned int i = 0; i < KEMN; i++)
        r->coeffs[i] = montred((int32_t)r->coeffs[i] * f);
}

void polyreduce(poly *r) {
    for (unsigned int i = 0; i < KEMN; i++)
        r->coeffs[i] = barrettred(r->coeffs[i]);
}

void polyadd(poly *r, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < KEMN; i++)
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
}

void polysub(poly *r, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < KEMN; i++)
        r->coeffs[i] = (int16_t)(a->coeffs[i] - b->coeffs[i]);
}

void pvcompress(uint8_t r[KEMPOLYVECCOMPRESSEDBYTES], const polyvec *a) {
    uint16_t t[8];
    for (unsigned int i = 0; i < KEMK; i++) {
        for (unsigned int j = 0; j < KEMN / 8; j++) {
            for (unsigned int k = 0; k < 8; k++) {
                t[k] = (uint16_t)a->vec[i].coeffs[8 * j + k];
                t[k] = (uint16_t)(t[k] + ((((int16_t)t[k]) >> 15) & KEMQ));
                uint64_t d0 = t[k];
                d0 <<= 11;
                d0 += 1664;
                d0 *= 645084;
                d0 >>= 31;
                t[k] = (uint16_t)(d0 & 0x7ff);
            }
            r[ 0] = (uint8_t)(t[0] >> 0);
            r[ 1] = (uint8_t)((t[0] >> 8) | (t[1] << 3));
            r[ 2] = (uint8_t)((t[1] >> 5) | (t[2] << 6));
            r[ 3] = (uint8_t)(t[2] >> 2);
            r[ 4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
            r[ 5] = (uint8_t)((t[3] >> 7) | (t[4] << 4));
            r[ 6] = (uint8_t)((t[4] >> 4) | (t[5] << 7));
            r[ 7] = (uint8_t)(t[5] >> 1);
            r[ 8] = (uint8_t)((t[5] >> 9) | (t[6] << 2));
            r[ 9] = (uint8_t)((t[6] >> 6) | (t[7] << 5));
            r[10] = (uint8_t)(t[7] >> 3);
            r += 11;
        }
    }
}

void pvdecompress(polyvec *r, const uint8_t a[KEMPOLYVECCOMPRESSEDBYTES]) {
    uint16_t t[8];
    for (unsigned int i = 0; i < KEMK; i++) {
        for (unsigned int j = 0; j < KEMN / 8; j++) {
            t[0] = (uint16_t)((a[0] >> 0) | ((uint16_t)a[ 1] << 8));
            t[1] = (uint16_t)((a[1] >> 3) | ((uint16_t)a[ 2] << 5));
            t[2] = (uint16_t)((a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10));
            t[3] = (uint16_t)((a[4] >> 1) | ((uint16_t)a[ 5] << 7));
            t[4] = (uint16_t)((a[5] >> 4) | ((uint16_t)a[ 6] << 4));
            t[5] = (uint16_t)((a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9));
            t[6] = (uint16_t)((a[8] >> 2) | ((uint16_t)a[ 9] << 6));
            t[7] = (uint16_t)((a[9] >> 5) | ((uint16_t)a[10] << 3));
            a += 11;
            for (unsigned int k = 0; k < 8; k++)
                r->vec[i].coeffs[8 * j + k] = (int16_t)(((uint32_t)(t[k] & 0x7FF) * KEMQ + 1024) >> 11);
        }
    }
}

void pvtobytes(uint8_t r[KEMPOLYVECBYTES], const polyvec *a) {
    for (unsigned int i = 0; i < KEMK; i++)
        polytobytes(r + i * KEMPOLYBYTES, &a->vec[i]);
}

void pvfrombytes(polyvec *r, const uint8_t a[KEMPOLYVECBYTES]) {
    for (unsigned int i = 0; i < KEMK; i++)
        polyfrombytes(&r->vec[i], a + i * KEMPOLYBYTES);
}

void pvntt(polyvec *r) {
    for (unsigned int i = 0; i < KEMK; i++) polyntt(&r->vec[i]);
}

void pvinvntttomont(polyvec *r) {
    for (unsigned int i = 0; i < KEMK; i++) polyinvntttomont(&r->vec[i]);
}

void pvbasemulaccmont(poly *r, const polyvec *a, const polyvec *b) {
    poly t;
    polybasemulmont(r, &a->vec[0], &b->vec[0]);
    for (unsigned int i = 1; i < KEMK; i++) {
        polybasemulmont(&t, &a->vec[i], &b->vec[i]);
        polyadd(r, r, &t);
    }
    polyreduce(r);
}

void pvreduce(polyvec *r) {
    for (unsigned int i = 0; i < KEMK; i++) polyreduce(&r->vec[i]);
}

void pvadd(polyvec *r, const polyvec *a, const polyvec *b) {
    for (unsigned int i = 0; i < KEMK; i++) polyadd(&r->vec[i], &a->vec[i], &b->vec[i]);
}
