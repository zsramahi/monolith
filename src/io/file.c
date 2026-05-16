#include "file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fileexists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

int filesize(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    fclose(f);
    if (n < 0) return -1;
    *out = (uint64_t)n;
    return 0;
}

int slurp(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    uint8_t *b = (uint8_t *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return -1; }
    size_t got = fread(b, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(b); return -1; }
    *buf = b;
    *len = (size_t)n;
    return 0;
}

int spit(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = fwrite(buf, 1, len, f);
    int rc = (put == len) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}
