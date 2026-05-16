#include <stdio.h>
#include <string.h>
#include "genpair.h"
#include "../kem/kem.h"
#include "../io/pem.h"

#define LBLPUB "MONOLITH PUBLIC KEY"
#define LBLPRV "MONOLITH PRIVATE KEY"

int cmdgenpair(int argc, char **argv) {
    const char *outpub = NULL;
    const char *outprv = NULL;
    int force = 0;

    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "--out-public") == 0 && i + 1 < argc) { outpub = argv[++i]; continue; }
        if (strcmp(s, "--out-secret") == 0 && i + 1 < argc) { outprv = argv[++i]; continue; }
        if (strcmp(s, "--force") == 0 || strcmp(s, "-f") == 0) { force = 1; continue; }
        fprintf(stderr, "bad arg: %s\n", s);
        return 1;
    }
    if (!outpub || !outprv) {
        fprintf(stderr, "need --out-public <file> and --out-secret <file>\n");
        return 1;
    }

    uint8_t pk[KEMPUBKEYBYTES];
    uint8_t sk[KEMSECKEYBYTES];
    if (kemkeypair(pk, sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }
    if (pemwrite(outpub, LBLPUB, pk, KEMPUBKEYBYTES, force) != 0) return 1;
    if (pemwrite(outprv, LBLPRV, sk, KEMSECKEYBYTES, force) != 0) return 1;

    printf("public key written to %s (%d bytes raw, pem-wrapped)\n", outpub, KEMPUBKEYBYTES);
    printf("secret key written to %s (%d bytes raw, pem-wrapped)\n", outprv, KEMSECKEYBYTES);
    return 0;
}
