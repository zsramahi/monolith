#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "selftest.h"
#include "../core/perm.h"
#include "../core/duplex.h"
#include "../util/hex.h"
#include "../kem/kem.h"

static int permdeterminism(void) {
    uint64_t a[16], b[16];
    for (int i = 0; i < 16; i++) { a[i] = (uint64_t)i; b[i] = (uint64_t)i; }
    monolithperm(a);
    monolithperm(b);
    for (int i = 0; i < 16; i++) if (a[i] != b[i]) return -1;
    return 0;
}

static int permavalanche(void) {
    uint64_t a[16], b[16];
    for (int i = 0; i < 16; i++) { a[i] = 0; b[i] = 0; }
    b[7] = 1;
    monolithperm(a);
    monolithperm(b);
    int diffbits = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t x = a[i] ^ b[i];
        for (int k = 0; k < 64; k++) if ((x >> k) & 1) diffbits++;
    }
    if (diffbits < 400 || diffbits > 624) return -1;
    return 0;
}

static int rt(size_t len) {
    uint8_t key[32], nonce[16];
    for (int i = 0; i < 32; i++) key[i]   = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(i * 13 + 5);

    uint8_t *pt = (uint8_t *)malloc(len ? len : 1);
    uint8_t *ct = (uint8_t *)malloc(len ? len : 1);
    uint8_t *rb = (uint8_t *)malloc(len ? len : 1);
    if (!pt || !ct || !rb) { free(pt); free(ct); free(rb); return -1; }
    for (size_t i = 0; i < len; i++) pt[i] = (uint8_t)((i * 31 + 11) & 0xFF);

    mono e, d;
    uint8_t etag[16], dtag[16];
    monoinit(&e, key, nonce);
    monoencrypt(&e, pt, ct, len);
    monofinish(&e, etag);

    monoinit(&d, key, nonce);
    monodecrypt(&d, ct, rb, len);
    monofinish(&d, dtag);

    int rc = 0;
    if (memcmp(pt, rb, len) != 0) rc = -1;
    if (monoctcompare(etag, dtag, 16) != 0) rc = -1;

    free(pt); free(ct); free(rb);
    return rc;
}

static int tamper(void) {
    uint8_t key[32] = {0}, nonce[16] = {0};
    uint8_t pt[100], ct[100], rb[100];
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)i;

    mono e;
    uint8_t etag[16], dtag[16];
    monoinit(&e, key, nonce);
    monoencrypt(&e, pt, ct, 100);
    monofinish(&e, etag);

    ct[42] ^= 1;

    mono d;
    monoinit(&d, key, nonce);
    monodecrypt(&d, ct, rb, 100);
    monofinish(&d, dtag);

    return monoctcompare(etag, dtag, 16) == 0 ? -1 : 0;
}

static int wrongkey(void) {
    uint8_t k1[32] = {0}, k2[32] = {0}, nonce[16] = {0};
    k2[0] = 1;
    uint8_t pt[64], ct[64], rb[64];
    for (int i = 0; i < 64; i++) pt[i] = (uint8_t)i;

    mono e;
    uint8_t etag[16], dtag[16];
    monoinit(&e, k1, nonce);
    monoencrypt(&e, pt, ct, 64);
    monofinish(&e, etag);

    mono d;
    monoinit(&d, k2, nonce);
    monodecrypt(&d, ct, rb, 64);
    monofinish(&d, dtag);

    return monoctcompare(etag, dtag, 16) == 0 ? -1 : 0;
}

static int kat(void) {
    uint64_t s[16];
    for (int i = 0; i < 16; i++) s[i] = 0;
    monolithperm(s);

    uint8_t key[32] = {0}, nonce[16] = {0};
    uint8_t pt[64];
    for (int i = 0; i < 64; i++) pt[i] = (uint8_t)i;
    uint8_t ct[64], tag[16];
    mono m;
    monoinit(&m, key, nonce);
    monoencrypt(&m, pt, ct, 64);
    monofinish(&m, tag);

    char hexct[129], hextag[33];
    hexencode(ct, 64, hexct);
    hexencode(tag, 16, hextag);
    printf("kat: ct  = %s\n", hexct);
    printf("kat: tag = %s\n", hextag);
    return 0;
}

static int kemroundtrip(void) {
    uint8_t pk[KEMPUBKEYBYTES], sk[KEMSECKEYBYTES];
    uint8_t ct[KEMCTBYTES], ssA[KEMSSBYTES], ssB[KEMSSBYTES];
    if (kemkeypair(pk, sk) != 0) return -1;
    if (kemencaps(ct, ssA, pk) != 0) return -1;
    if (kemdecaps(ssB, ct, sk) != 0) return -1;
    return monoctcompare(ssA, ssB, KEMSSBYTES) == 0 ? 0 : -1;
}

static int kemtamper(void) {
    uint8_t pk[KEMPUBKEYBYTES], sk[KEMSECKEYBYTES];
    uint8_t ct[KEMCTBYTES], ssA[KEMSSBYTES], ssB[KEMSSBYTES];
    if (kemkeypair(pk, sk) != 0) return -1;
    if (kemencaps(ct, ssA, pk) != 0) return -1;
    ct[100] ^= 1;
    kemdecaps(ssB, ct, sk);
    return monoctcompare(ssA, ssB, KEMSSBYTES) != 0 ? 0 : -1;
}

int cmdselftest(int argc, char **argv) {
    (void)argc; (void)argv;
    struct { const char *name; int (*fn)(void); } cases[] = {
        { "perm determinism", permdeterminism },
        { "perm avalanche",   permavalanche  },
        { "tamper detect",    tamper         },
        { "wrong key",        wrongkey       },
        { "kem roundtrip",    kemroundtrip   },
        { "kem tamper",       kemtamper      },
    };
    int fail = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = cases[i].fn();
        printf("%-20s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) fail = 1;
    }
    size_t sizes[] = { 0, 1, 16, 63, 64, 65, 128, 1000, 1<<14, (1<<16) + 7 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        int rc = rt(sizes[i]);
        printf("rt size %-10llu %s\n", (unsigned long long)sizes[i], rc == 0 ? "ok" : "FAIL");
        if (rc != 0) fail = 1;
    }
    kat();
    return fail ? 1 : 0;
}
