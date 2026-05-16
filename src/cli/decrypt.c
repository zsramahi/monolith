#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decrypt.h"
#include "args.h"
#include "keyresolve.h"
#include "../core/duplex.h"
#include "../io/file.h"
#include "../io/format.h"
#include "../io/pem.h"
#include "../kem/kem.h"

#define CHUNK 65536

static char *stripmono(const char *in) {
    size_t n = strlen(in);
    if (n > 5 && strcmp(in + n - 5, ".mono") == 0) {
        char *out = (char *)malloc(n - 5 + 1);
        if (!out) return NULL;
        memcpy(out, in, n - 5);
        out[n - 5] = '\0';
        return out;
    }
    char *out = (char *)malloc(n + 5);
    if (!out) return NULL;
    memcpy(out, in, n);
    memcpy(out + n, ".out", 5);
    return out;
}

static int parsearg2(int argc, char **argv,
                     const char **input, const char **out, const char **key,
                     const char **secret, int *force) {
    *input = *out = *key = *secret = NULL;
    *force = 0;
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "--key")    == 0 && i + 1 < argc) { *key    = argv[++i]; continue; }
        if (strcmp(s, "--secret") == 0 && i + 1 < argc) { *secret = argv[++i]; continue; }
        if ((strcmp(s, "--out") == 0 || strcmp(s, "-o") == 0) && i + 1 < argc) { *out = argv[++i]; continue; }
        if (strcmp(s, "--force") == 0 || strcmp(s, "-f") == 0) { *force = 1; continue; }
        if (s[0] == '-' && s[1] != '\0') { fprintf(stderr, "bad flag: %s\n", s); return -1; }
        if (*input != NULL) { fprintf(stderr, "extra arg: %s\n", s); return -1; }
        *input = s;
    }
    return 0;
}

int cmddecrypt(int argc, char **argv) {
    const char *input, *outarg, *keyarg, *secretarg;
    int force;
    if (parsearg2(argc, argv, &input, &outarg, &keyarg, &secretarg, &force) != 0) return 1;
    if (!input) { fprintf(stderr, "missing input file\n"); return 1; }
    if (!keyarg && !secretarg) {
        fprintf(stderr, "specify --key (symmetric) or --secret (private key)\n");
        return 1;
    }
    if (keyarg && secretarg) {
        fprintf(stderr, "use only one of --key or --secret\n");
        return 1;
    }

    uint64_t total = 0;
    if (filesize(input, &total) != 0) {
        fprintf(stderr, "cannot stat %s\n", input);
        return 1;
    }
    if (total < (uint64_t)(MONO_HEADERSIZE + MONOLITH_TAGBYTES)) {
        fprintf(stderr, "file too small to be a .mono file\n");
        return 1;
    }

    FILE *fin = fopen(input, "rb");
    if (!fin) { fprintf(stderr, "cannot open %s\n", input); return 1; }

    uint8_t hdr[MONO_HEADERSIZE];
    if (fread(hdr, 1, MONO_HEADERSIZE, fin) != MONO_HEADERSIZE) {
        fprintf(stderr, "read failed\n"); fclose(fin); return 1;
    }
    monoheader h;
    int prc = parseheader(hdr, &h);
    if (prc != 0) {
        fprintf(stderr, "not a valid monolith file\n");
        fclose(fin); return 1;
    }

    int kemwrapped = (h.flags & MONO_FLAG_KEM) ? 1 : 0;
    if ((h.flags & ~MONO_FLAG_KEM) != 0) {
        fprintf(stderr, "unsupported flags 0x%02x\n", (unsigned)h.flags);
        fclose(fin); return 1;
    }
    if (kemwrapped && !secretarg) {
        fprintf(stderr, "this file was encrypted to a public key; use --secret\n");
        fclose(fin); return 1;
    }
    if (!kemwrapped && !keyarg) {
        fprintf(stderr, "this file uses a symmetric key; use --key\n");
        fclose(fin); return 1;
    }

    uint8_t key[32];
    uint64_t prefix = 0;
    if (kemwrapped) {
        prefix = KEMCTBYTES;
        if (total < (uint64_t)(MONO_HEADERSIZE + prefix + MONOLITH_TAGBYTES)) {
            fprintf(stderr, "file too small for kem-wrapped layout\n");
            fclose(fin); return 1;
        }
        uint8_t sk[KEMSECKEYBYTES];
        size_t sklen = 0;
        if (pemread(secretarg, "MONOLITH PRIVATE KEY", sk, KEMSECKEYBYTES, &sklen) != 0) {
            fclose(fin); return 1;
        }
        if (sklen != KEMSECKEYBYTES) {
            fprintf(stderr, "wrong private key size\n"); fclose(fin); return 1;
        }
        uint8_t ct[KEMCTBYTES];
        if (fread(ct, 1, KEMCTBYTES, fin) != KEMCTBYTES) {
            fprintf(stderr, "read failed\n"); fclose(fin); return 1;
        }
        uint8_t ss[KEMSSBYTES];
        kemdecaps(ss, ct, sk);
        memcpy(key, ss, 32);
    } else {
        if (resolvekey(keyarg, key) != 0) { fclose(fin); return 1; }
    }

    char *outpath = NULL;
    if (outarg) {
        outpath = (char *)malloc(strlen(outarg) + 1);
        if (!outpath) { fclose(fin); return 1; }
        strcpy(outpath, outarg);
    } else {
        outpath = stripmono(input);
        if (!outpath) { fclose(fin); return 1; }
    }
    if (!force && fileexists(outpath)) {
        fprintf(stderr, "refusing to overwrite %s (use --force)\n", outpath);
        fclose(fin); free(outpath); return 1;
    }
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { fprintf(stderr, "cannot create %s\n", outpath); fclose(fin); free(outpath); return 1; }

    uint64_t cipherlen = total - MONO_HEADERSIZE - prefix - MONOLITH_TAGBYTES;

    mono m;
    monoinit(&m, key, h.nonce);

    uint8_t *inbuf  = (uint8_t *)malloc(CHUNK);
    uint8_t *outbuf = (uint8_t *)malloc(CHUNK);
    if (!inbuf || !outbuf) {
        free(inbuf); free(outbuf);
        fclose(fin); fclose(fout); remove(outpath); free(outpath); return 1;
    }

    int rc = 0;
    uint64_t remaining = cipherlen;
    while (remaining > 0) {
        size_t want = (remaining > CHUNK) ? CHUNK : (size_t)remaining;
        size_t got = fread(inbuf, 1, want, fin);
        if (got != want) { rc = 3; break; }
        monodecrypt(&m, inbuf, outbuf, got);
        if (fwrite(outbuf, 1, got, fout) != got) { rc = 3; break; }
        remaining -= got;
    }

    uint8_t tagfile[MONOLITH_TAGBYTES];
    if (rc == 0) {
        if (fread(tagfile, 1, MONOLITH_TAGBYTES, fin) != MONOLITH_TAGBYTES) rc = 3;
    }
    free(inbuf); free(outbuf);
    fclose(fin);

    if (rc == 0) {
        uint8_t tag[MONOLITH_TAGBYTES];
        monofinish(&m, tag);
        if (monoctcompare(tag, tagfile, MONOLITH_TAGBYTES) != 0) {
            fprintf(stderr, "authentication failed: tag mismatch\n");
            rc = 2;
        }
    }
    if (fclose(fout) != 0 && rc == 0) rc = 3;
    if (rc != 0) remove(outpath);
    free(outpath);
    return rc;
}
