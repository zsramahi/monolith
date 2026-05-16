#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inspect.h"
#include "args.h"
#include "../io/file.h"
#include "../io/format.h"
#include "../core/duplex.h"
#include "../kem/params.h"

int cmdinspect(int argc, char **argv) {
    cliargs a;
    argsinit(&a);
    if (argsparse(&a, argc, argv, 2) != 0) {
        fprintf(stderr, "bad arg: %s\n", a.errmsg ? a.errmsg : "?");
        return 1;
    }
    if (!a.input) { fprintf(stderr, "missing file\n"); return 1; }

    uint64_t total = 0;
    if (filesize(a.input, &total) != 0) {
        fprintf(stderr, "cannot stat %s\n", a.input);
        return 1;
    }
    if (total < (uint64_t)(MONO_HEADERSIZE + MONOLITH_TAGBYTES)) {
        fprintf(stderr, "file too small to be a .mono file\n");
        return 1;
    }

    FILE *f = fopen(a.input, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", a.input); return 1; }

    uint8_t hdr[MONO_HEADERSIZE];
    size_t got = fread(hdr, 1, MONO_HEADERSIZE, f);
    fclose(f);
    if (got != MONO_HEADERSIZE) { fprintf(stderr, "read failed\n"); return 1; }

    monoheader h;
    int prc = parseheader(hdr, &h);
    if (prc != 0) {
        fprintf(stderr, "not a valid monolith file\n");
        return 1;
    }

    uint64_t cipherlen = total - MONO_HEADERSIZE - MONOLITH_TAGBYTES;
    int kemwrapped = (h.flags & MONO_FLAG_KEM) ? 1 : 0;
    if (kemwrapped) cipherlen -= KEMCTBYTES;

    printf("file:        %s\n", a.input);
    printf("size:        %llu bytes (%llu ciphertext + %u framing%s)\n",
           (unsigned long long)total,
           (unsigned long long)cipherlen,
           (unsigned)(MONO_HEADERSIZE + MONOLITH_TAGBYTES),
           kemwrapped ? " + kem header" : "");
    printf("magic:       MONO\n");
    printf("version:     %u\n", (unsigned)h.version);
    printf("flags:       0x%02x%s\n", (unsigned)h.flags,
           kemwrapped ? " (kem-wrapped, requires --secret to decrypt)" : "");
    printf("nonce:       ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", h.nonce[i]);
        if (i < 15) printf(" ");
    }
    printf("\n");
    return 0;
}
