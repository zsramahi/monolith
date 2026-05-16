#include "b64.h"

static const char ALPH[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64encsize(size_t in) {
    return ((in + 2) / 3) * 4;
}

size_t b64decsize(size_t in) {
    return (in / 4) * 3;
}

void b64encode(const uint8_t *in, size_t inlen, char *out) {
    size_t i, j;
    for (i = 0, j = 0; i + 3 <= inlen; i += 3, j += 4) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[j + 0] = ALPH[(v >> 18) & 0x3F];
        out[j + 1] = ALPH[(v >> 12) & 0x3F];
        out[j + 2] = ALPH[(v >>  6) & 0x3F];
        out[j + 3] = ALPH[(v >>  0) & 0x3F];
    }
    size_t rem = inlen - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[j + 0] = ALPH[(v >> 18) & 0x3F];
        out[j + 1] = ALPH[(v >> 12) & 0x3F];
        out[j + 2] = '=';
        out[j + 3] = '=';
        j += 4;
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[j + 0] = ALPH[(v >> 18) & 0x3F];
        out[j + 1] = ALPH[(v >> 12) & 0x3F];
        out[j + 2] = ALPH[(v >>  6) & 0x3F];
        out[j + 3] = '=';
        j += 4;
    }
    out[j] = '\0';
}

static int decchar(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64decode(const char *in, size_t inlen, uint8_t *out, size_t *outlen) {
    if (inlen % 4 != 0) return -1;
    size_t pad = 0;
    if (inlen >= 1 && in[inlen - 1] == '=') pad++;
    if (inlen >= 2 && in[inlen - 2] == '=') pad++;
    size_t triples = inlen / 4;
    size_t produced = 0;
    for (size_t k = 0; k < triples; k++) {
        int c0 = decchar(in[4 * k + 0]);
        int c1 = decchar(in[4 * k + 1]);
        int c2 = (in[4 * k + 2] == '=') ? 0 : decchar(in[4 * k + 2]);
        int c3 = (in[4 * k + 3] == '=') ? 0 : decchar(in[4 * k + 3]);
        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return -1;
        uint32_t v = ((uint32_t)c0 << 18) | ((uint32_t)c1 << 12)
                   | ((uint32_t)c2 << 6)  | (uint32_t)c3;
        out[produced++] = (uint8_t)(v >> 16);
        if (k < triples - 1 || pad < 2) out[produced++] = (uint8_t)(v >> 8);
        if (k < triples - 1 || pad < 1) out[produced++] = (uint8_t)v;
    }
    *outlen = produced;
    return 0;
}
