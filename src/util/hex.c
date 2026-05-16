#include "hex.h"

static const char DIGITS[] = "0123456789abcdef";

void hexencode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = DIGITS[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = DIGITS[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static int nyb(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hexdecode(const char *in, size_t len, uint8_t *out) {
    if (len & 1) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = nyb((unsigned char)in[2 * i]);
        int lo = nyb((unsigned char)in[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
