#include "reduce.h"

int16_t montred(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * KEMQINV);
    t = (int16_t)((a - (int32_t)t * KEMQ) >> 16);
    return t;
}

int16_t barrettred(int16_t a) {
    const int16_t v = (int16_t)(((1 << 26) + KEMQ / 2) / KEMQ);
    int16_t t = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t = (int16_t)(t * KEMQ);
    return (int16_t)(a - t);
}
