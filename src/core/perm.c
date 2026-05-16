#include "perm.h"

static inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

#define QUAD(a, b, c, d)                                  \
    do {                                                  \
        a += b; d = rotl64(d ^ a, MONOLITH_R0);           \
        c += d; b = rotl64(b ^ c, MONOLITH_R1);           \
        a += b; d = rotl64(d ^ a, MONOLITH_R2);           \
        c += d; b = rotl64(b ^ c, MONOLITH_R3);           \
    } while (0)

void monolithperm(uint64_t s[MONOLITH_LANES]) {
    for (int r = 0; r < MONOLITH_ROUNDS; r++) {
        s[0] ^= MONOLITH_RC[r];
        switch (r & 3) {
            case 0:
                QUAD(s[0],  s[1],  s[2],  s[3]);
                QUAD(s[4],  s[5],  s[6],  s[7]);
                QUAD(s[8],  s[9],  s[10], s[11]);
                QUAD(s[12], s[13], s[14], s[15]);
                break;
            case 1:
                QUAD(s[0], s[4], s[8],  s[12]);
                QUAD(s[1], s[5], s[9],  s[13]);
                QUAD(s[2], s[6], s[10], s[14]);
                QUAD(s[3], s[7], s[11], s[15]);
                break;
            case 2:
                QUAD(s[0], s[5], s[10], s[15]);
                QUAD(s[1], s[6], s[11], s[12]);
                QUAD(s[2], s[7], s[8],  s[13]);
                QUAD(s[3], s[4], s[9],  s[14]);
                break;
            case 3:
                QUAD(s[3], s[6], s[9],  s[12]);
                QUAD(s[2], s[5], s[8],  s[15]);
                QUAD(s[1], s[4], s[11], s[14]);
                QUAD(s[0], s[7], s[10], s[13]);
                break;
        }
    }
}
