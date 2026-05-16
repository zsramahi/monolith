/*
 * cca-secure kem (fujisaki-okamoto transform) for monolith.
 * adapted from the public-domain crystals-kyber reference (cc0 / apache 2.0).
 */

#include <stddef.h>
#include <string.h>
#include "kem.h"
#include "indcpa.h"
#include "keccak.h"
#include "../util/rng.h"

int ctcompare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t r = 0;
    for (size_t i = 0; i < len; i++) r |= (uint8_t)(a[i] ^ b[i]);
    return (int)((-(uint64_t)r) >> 63);
}

void ctcmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    b = (uint8_t)(-b);
    for (size_t i = 0; i < len; i++)
        r[i] ^= (uint8_t)(b & (r[i] ^ x[i]));
}

static void rkprf(uint8_t out[KEMSSBYTES], const uint8_t key[KEMSYMBYTES], const uint8_t input[KEMCTBYTES]) {
    keccak st;
    shake256init(&st);
    shake256absorb(&st, key, KEMSYMBYTES);
    shake256absorb(&st, input, KEMCTBYTES);
    shake256finalize(&st);
    shake256squeeze(out, KEMSSBYTES, &st);
}

int kemkeypair(uint8_t pk[KEMPUBKEYBYTES], uint8_t sk[KEMSECKEYBYTES]) {
    uint8_t coins[2 * KEMSYMBYTES];
    if (rngfill(coins, 2 * KEMSYMBYTES) != 0) return -1;

    indcpakeypair(pk, sk, coins);
    memcpy(sk + KEMINDCPASECKEYBYTES, pk, KEMPUBKEYBYTES);
    sha3256(sk + KEMSECKEYBYTES - 2 * KEMSYMBYTES, pk, KEMPUBKEYBYTES);
    memcpy(sk + KEMSECKEYBYTES - KEMSYMBYTES, coins + KEMSYMBYTES, KEMSYMBYTES);
    return 0;
}

int kemencaps(uint8_t ct[KEMCTBYTES], uint8_t ss[KEMSSBYTES], const uint8_t pk[KEMPUBKEYBYTES]) {
    uint8_t coins[KEMSYMBYTES];
    if (rngfill(coins, KEMSYMBYTES) != 0) return -1;

    uint8_t buf[2 * KEMSYMBYTES];
    uint8_t kr[2 * KEMSYMBYTES];

    memcpy(buf, coins, KEMSYMBYTES);
    sha3256(buf + KEMSYMBYTES, pk, KEMPUBKEYBYTES);
    sha3512(kr, buf, 2 * KEMSYMBYTES);

    indcpaenc(ct, buf, pk, kr + KEMSYMBYTES);
    memcpy(ss, kr, KEMSYMBYTES);
    return 0;
}

int kemdecaps(uint8_t ss[KEMSSBYTES], const uint8_t ct[KEMCTBYTES], const uint8_t sk[KEMSECKEYBYTES]) {
    uint8_t buf[2 * KEMSYMBYTES];
    uint8_t kr[2 * KEMSYMBYTES];
    uint8_t cmp[KEMCTBYTES];
    const uint8_t *pk = sk + KEMINDCPASECKEYBYTES;

    indcpadec(buf, ct, sk);
    memcpy(buf + KEMSYMBYTES, sk + KEMSECKEYBYTES - 2 * KEMSYMBYTES, KEMSYMBYTES);
    sha3512(kr, buf, 2 * KEMSYMBYTES);

    indcpaenc(cmp, buf, pk, kr + KEMSYMBYTES);
    int fail = ctcompare(ct, cmp, KEMCTBYTES);

    rkprf(ss, sk + KEMSECKEYBYTES - KEMSYMBYTES, ct);
    ctcmov(ss, kr, KEMSYMBYTES, (uint8_t)(!fail));
    return 0;
}
