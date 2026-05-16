#ifndef MONOLITH_KEMPOLY_H
#define MONOLITH_KEMPOLY_H

#include <stdint.h>
#include "params.h"

typedef struct { int16_t coeffs[KEMN]; } poly;
typedef struct { poly vec[KEMK]; } polyvec;

extern const int16_t zetas[128];

void ntt(int16_t r[256]);
void invntt(int16_t r[256]);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

void polycompress(uint8_t r[KEMPOLYCOMPRESSEDBYTES], const poly *a);
void polydecompress(poly *r, const uint8_t a[KEMPOLYCOMPRESSEDBYTES]);
void polytobytes(uint8_t r[KEMPOLYBYTES], const poly *a);
void polyfrombytes(poly *r, const uint8_t a[KEMPOLYBYTES]);
void polyfrommsg(poly *r, const uint8_t msg[KEMINDCPAMSGBYTES]);
void polytomsg(uint8_t msg[KEMINDCPAMSGBYTES], const poly *a);
void polynoiseeta1(poly *r, const uint8_t seed[KEMSYMBYTES], uint8_t nonce);
void polynoiseeta2(poly *r, const uint8_t seed[KEMSYMBYTES], uint8_t nonce);
void polyntt(poly *r);
void polyinvntttomont(poly *r);
void polybasemulmont(poly *r, const poly *a, const poly *b);
void polytomont(poly *r);
void polyreduce(poly *r);
void polyadd(poly *r, const poly *a, const poly *b);
void polysub(poly *r, const poly *a, const poly *b);

void pvcompress(uint8_t r[KEMPOLYVECCOMPRESSEDBYTES], const polyvec *a);
void pvdecompress(polyvec *r, const uint8_t a[KEMPOLYVECCOMPRESSEDBYTES]);
void pvtobytes(uint8_t r[KEMPOLYVECBYTES], const polyvec *a);
void pvfrombytes(polyvec *r, const uint8_t a[KEMPOLYVECBYTES]);
void pvntt(polyvec *r);
void pvinvntttomont(polyvec *r);
void pvbasemulaccmont(poly *r, const polyvec *a, const polyvec *b);
void pvreduce(polyvec *r);
void pvadd(polyvec *r, const polyvec *a, const polyvec *b);

#endif
