#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pem.h"
#include "file.h"
#include "../util/b64.h"

#define LINELEN 64

int pemwrite(const char *path, const char *label, const uint8_t *data, size_t len, int force) {
    if (!force && fileexists(path)) {
        fprintf(stderr, "refusing to overwrite %s (use --force)\n", path);
        return -1;
    }
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot create %s\n", path); return -1; }

    size_t encsz = b64encsize(len);
    char *enc = (char *)malloc(encsz + 1);
    if (!enc) { fclose(f); return -1; }
    b64encode(data, len, enc);

    fprintf(f, "-----BEGIN %s-----\n", label);
    for (size_t off = 0; off < encsz; off += LINELEN) {
        size_t n = encsz - off;
        if (n > LINELEN) n = LINELEN;
        fwrite(enc + off, 1, n, f);
        fputc('\n', f);
    }
    fprintf(f, "-----END %s-----\n", label);

    free(enc);
    if (fclose(f) != 0) return -1;
    return 0;
}

int pemread(const char *path, const char *label, uint8_t *out, size_t outcap, size_t *outlen) {
    uint8_t *raw = NULL;
    size_t rlen = 0;
    if (slurp(path, &raw, &rlen) != 0) {
        fprintf(stderr, "cannot read %s\n", path);
        return -1;
    }

    char beg[96], end[96];
    int bn = snprintf(beg, sizeof(beg), "-----BEGIN %s-----", label);
    int en = snprintf(end, sizeof(end), "-----END %s-----",   label);
    if (bn <= 0 || en <= 0) { free(raw); return -1; }

    char *txt = (char *)malloc(rlen + 1);
    if (!txt) { free(raw); return -1; }
    memcpy(txt, raw, rlen);
    txt[rlen] = '\0';
    free(raw);

    char *bp = strstr(txt, beg);
    char *ep = strstr(txt, end);
    if (!bp || !ep || ep <= bp) {
        fprintf(stderr, "missing %s envelope in %s\n", label, path);
        free(txt);
        return -1;
    }
    bp += bn;

    size_t cap = (size_t)(ep - bp);
    char *clean = (char *)malloc(cap + 1);
    if (!clean) { free(txt); return -1; }
    size_t cn = 0;
    for (size_t i = 0; i < cap; i++) {
        char c = bp[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        clean[cn++] = c;
    }

    if (b64decsize(cn) > outcap + 3) {
        fprintf(stderr, "pem body too large for %s\n", label);
        free(clean); free(txt);
        return -1;
    }

    uint8_t *tmp = (uint8_t *)malloc(b64decsize(cn) + 4);
    if (!tmp) { free(clean); free(txt); return -1; }
    size_t produced = 0;
    int rc = b64decode(clean, cn, tmp, &produced);
    free(clean);
    if (rc != 0 || produced > outcap) {
        fprintf(stderr, "bad base64 or size mismatch in %s\n", path);
        free(tmp); free(txt);
        return -1;
    }
    memcpy(out, tmp, produced);
    *outlen = produced;
    free(tmp); free(txt);
    return 0;
}
