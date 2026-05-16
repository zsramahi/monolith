#ifndef MONOLITH_DUPLEX_H
#define MONOLITH_DUPLEX_H

#include <stdint.h>
#include <stddef.h>
#include "consts.h"

typedef struct {
    uint64_t s[MONOLITH_LANES];
    uint8_t buf[MONOLITH_RATEBYTES];
    size_t buflen;
} mono;

void monoinit(mono *m, const uint8_t key[MONOLITH_KEYBYTES],
              const uint8_t nonce[MONOLITH_NONCEBYTES]);

void monoencrypt(mono *m, const uint8_t *in, uint8_t *out, size_t len);
void monodecrypt(mono *m, const uint8_t *in, uint8_t *out, size_t len);

void monofinish(mono *m, uint8_t tag[MONOLITH_TAGBYTES]);

int monoctcompare(const uint8_t *a, const uint8_t *b, size_t n);

#endif
