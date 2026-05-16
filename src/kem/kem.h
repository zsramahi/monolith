#ifndef MONOLITH_KEM_H
#define MONOLITH_KEM_H

#include <stdint.h>
#include "params.h"

int kemkeypair(uint8_t pk[KEMPUBKEYBYTES], uint8_t sk[KEMSECKEYBYTES]);
int kemencaps(uint8_t ct[KEMCTBYTES], uint8_t ss[KEMSSBYTES], const uint8_t pk[KEMPUBKEYBYTES]);
int kemdecaps(uint8_t ss[KEMSSBYTES], const uint8_t ct[KEMCTBYTES], const uint8_t sk[KEMSECKEYBYTES]);

int ctcompare(const uint8_t *a, const uint8_t *b, size_t len);
void ctcmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif
