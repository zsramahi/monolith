#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyresolve.h"
#include "../io/file.h"
#include "../util/hex.h"

static int allhex(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}

static int loadhexkeyfile(const uint8_t *data, size_t len, uint8_t key[32]) {
    char clean[128];
    size_t n = 0;
    for (size_t i = 0; i < len && n < sizeof(clean); i++) {
        char c = (char)data[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        clean[n++] = c;
    }
    if (n != 64) return -1;
    if (!allhex(clean, 64)) return -1;
    return hexdecode(clean, 64, key);
}

int resolvekey(const char *spec, uint8_t key[32]) {
    if (!spec) return -1;
    size_t slen = strlen(spec);
    if (slen == 64 && allhex(spec, 64)) {
        return hexdecode(spec, 64, key) == 0 ? 0 : -1;
    }
    uint8_t *raw = NULL;
    size_t rlen = 0;
    if (slurp(spec, &raw, &rlen) != 0) {
        fprintf(stderr, "cannot read key file: %s\n", spec);
        return -1;
    }
    int rc;
    if (rlen == 32) {
        memcpy(key, raw, 32);
        rc = 0;
    } else {
        rc = loadhexkeyfile(raw, rlen, key);
        if (rc != 0) {
            fprintf(stderr, "key file is neither 32 raw bytes nor 64 hex chars: %s\n", spec);
        }
    }
    free(raw);
    return rc;
}
