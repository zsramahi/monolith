#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encrypt.h"
#include "args.h"
#include "keyresolve.h"
#include "../core/duplex.h"
#include "../io/file.h"
#include "../io/format.h"
#include "../io/pem.h"
#include "../kem/kem.h"
#include "../util/rng.h"

#define CHUNK 65536

static char *suffixmono(const char *in) {
    size_t n = strlen(in);
    char *out = (char *)malloc(n + 6);
    if (!out) return NULL;
    memcpy(out, in, n);
    memcpy(out + n, ".mono", 6);
    return out;
}

static int parsearg2(int argc, char **argv,
                     const char **input, const char **out, const char **key,
                     const char **to, int *force) {
    *input = *out = *key = *to = NULL;
    *force = 0;
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "--key") == 0 && i + 1 < argc) { *key = argv[++i]; continue; }
        if (strcmp(s, "--to")  == 0 && i + 1 < argc) { *to  = argv[++i]; continue; }
        if ((strcmp(s, "--out") == 0 || strcmp(s, "-o") == 0) && i + 1 < argc) { *out = argv[++i]; continue; }
        if (strcmp(s, "--force") == 0 || strcmp(s, "-f") == 0) { *force = 1; continue; }
        if (s[0] == '-' && s[1] != '\0') { fprintf(stderr, "bad flag: %s\n", s); return -1; }
        if (*input != NULL) { fprintf(stderr, "extra arg: %s\n", s); return -1; }
        *input = s;
    }
    return 0;
}

int cmdencrypt(int argc, char **argv) {
    const char *input, *outarg, *keyarg, *toarg;
    int force;
    if (parsearg2(argc, argv, &input, &outarg, &keyarg, &toarg, &force) != 0) return 1;
    if (!input) { fprintf(stderr, "missing input file\n"); return 1; }
    if (!keyarg && !toarg) { fprintf(stderr, "specify --key (symmetric) or --to (public key)\n"); return 1; }
    if (keyarg && toarg)   { fprintf(stderr, "use only one of --key or --to\n"); return 1; }

    uint8_t key[32];
    uint8_t kemct[KEMCTBYTES];
    int usingkem = 0;

    if (toarg) {
        usingkem = 1;
        uint8_t pk[KEMPUBKEYBYTES];
        size_t pklen = 0;
        if (pemread(toarg, "MONOLITH PUBLIC KEY", pk, KEMPUBKEYBYTES, &pklen) != 0) return 1;
        if (pklen != KEMPUBKEYBYTES) {
            fprintf(stderr, "wrong public key size: got %llu bytes, expected %d\n",
                    (unsigned long long)pklen, KEMPUBKEYBYTES);
            return 1;
        }
        uint8_t ss[KEMSSBYTES];
        if (kemencaps(kemct, ss, pk) != 0) {
            fprintf(stderr, "kem encapsulation failed\n");
            return 1;
        }
        memcpy(key, ss, 32);
    } else {
        if (resolvekey(keyarg, key) != 0) return 1;
    }

    char *outpath = NULL;
    if (outarg) {
        outpath = (char *)malloc(strlen(outarg) + 1);
        if (!outpath) return 1;
        strcpy(outpath, outarg);
    } else {
        outpath = suffixmono(input);
        if (!outpath) return 1;
    }
    if (!force && fileexists(outpath)) {
        fprintf(stderr, "refusing to overwrite %s (use --force)\n", outpath);
        free(outpath); return 1;
    }

    FILE *fin = fopen(input, "rb");
    if (!fin) { fprintf(stderr, "cannot open %s\n", input); free(outpath); return 1; }
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { fprintf(stderr, "cannot create %s\n", outpath); fclose(fin); free(outpath); return 1; }

    monoheader h;
    h.version = MONO_VERSION;
    h.flags = (uint8_t)(usingkem ? MONO_FLAG_KEM : 0);
    if (rngfill(h.nonce, 16) != 0) {
        fprintf(stderr, "rng failed\n");
        fclose(fin); fclose(fout); remove(outpath); free(outpath); return 1;
    }
    uint8_t hdr[MONO_HEADERSIZE];
    packheader(&h, hdr);
    if (fwrite(hdr, 1, MONO_HEADERSIZE, fout) != MONO_HEADERSIZE) {
        fprintf(stderr, "write failed\n");
        fclose(fin); fclose(fout); remove(outpath); free(outpath); return 3;
    }

    if (usingkem) {
        if (fwrite(kemct, 1, KEMCTBYTES, fout) != KEMCTBYTES) {
            fprintf(stderr, "write failed\n");
            fclose(fin); fclose(fout); remove(outpath); free(outpath); return 3;
        }
    }

    mono m;
    monoinit(&m, key, h.nonce);

    uint8_t *inbuf  = (uint8_t *)malloc(CHUNK);
    uint8_t *outbuf = (uint8_t *)malloc(CHUNK);
    if (!inbuf || !outbuf) {
        fprintf(stderr, "out of memory\n");
        free(inbuf); free(outbuf);
        fclose(fin); fclose(fout); remove(outpath); free(outpath); return 1;
    }

    int rc = 0;
    for (;;) {
        size_t got = fread(inbuf, 1, CHUNK, fin);
        if (got == 0) break;
        monoencrypt(&m, inbuf, outbuf, got);
        if (fwrite(outbuf, 1, got, fout) != got) { rc = 3; break; }
    }
    if (rc == 0 && ferror(fin)) rc = 3;

    if (rc == 0) {
        uint8_t tag[MONOLITH_TAGBYTES];
        monofinish(&m, tag);
        if (fwrite(tag, 1, MONOLITH_TAGBYTES, fout) != MONOLITH_TAGBYTES) rc = 3;
    }

    free(inbuf); free(outbuf);
    fclose(fin);
    fclose(fout);
    if (rc != 0) remove(outpath);
    free(outpath);
    return rc;
}
