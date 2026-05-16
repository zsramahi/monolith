#ifndef MONOLITH_KECCAK_H
#define MONOLITH_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128RATE 168
#define SHAKE256RATE 136
#define SHA3256RATE  136
#define SHA3512RATE  72

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak;

void shake128init(keccak *st);
void shake128absorbonce(keccak *st, const uint8_t *in, size_t inlen);
void shake128squeezeblocks(uint8_t *out, size_t nblocks, keccak *st);

void shake256init(keccak *st);
void shake256absorb(keccak *st, const uint8_t *in, size_t inlen);
void shake256finalize(keccak *st);
void shake256squeeze(uint8_t *out, size_t outlen, keccak *st);

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3512(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif
