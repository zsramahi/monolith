#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "genkey.h"
#include "args.h"
#include "../io/file.h"
#include "../util/rng.h"
#include "../util/hex.h"

int cmdgenkey(int argc, char **argv) {
    cliargs a;
    argsinit(&a);
    if (argsparse(&a, argc, argv, 2) != 0) {
        fprintf(stderr, "bad arg: %s\n", a.errmsg ? a.errmsg : "?");
        return 1;
    }
    int rawmode = 0;
    if (a.format) {
        if (strcmp(a.format, "raw") == 0)      rawmode = 1;
        else if (strcmp(a.format, "hex") == 0) rawmode = 0;
        else { fprintf(stderr, "--format must be hex or raw\n"); return 1; }
    }

    uint8_t key[32];
    if (rngfill(key, 32) != 0) {
        fprintf(stderr, "rng failed\n");
        return 1;
    }

    if (a.out) {
        if (!a.force && fileexists(a.out)) {
            fprintf(stderr, "refusing to overwrite %s (use --force)\n", a.out);
            return 1;
        }
        if (rawmode) {
            if (spit(a.out, key, 32) != 0) {
                fprintf(stderr, "write failed: %s\n", a.out);
                return 3;
            }
        } else {
            char hex[65];
            hexencode(key, 32, hex);
            hex[64] = '\n';
            if (spit(a.out, (const uint8_t *)hex, 65) != 0) {
                fprintf(stderr, "write failed: %s\n", a.out);
                return 3;
            }
        }
    } else {
        if (rawmode) {
            fwrite(key, 1, 32, stdout);
        } else {
            char hex[65];
            hexencode(key, 32, hex);
            puts(hex);
        }
    }
    return 0;
}
