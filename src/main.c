#include <stdio.h>
#include <string.h>
#include "cli/help.h"
#include "cli/genkey.h"
#include "cli/genpair.h"
#include "cli/encrypt.h"
#include "cli/decrypt.h"
#include "cli/inspect.h"
#include "cli/selftest.h"

int main(int argc, char **argv) {
    if (argc < 2) { cmdhelp(argc, argv); return 1; }
    const char *c = argv[1];
    if (strcmp(c, "help") == 0 || strcmp(c, "-h") == 0 || strcmp(c, "--help") == 0)
        return cmdhelp(argc, argv);
    if (strcmp(c, "version") == 0 || strcmp(c, "-v") == 0 || strcmp(c, "--version") == 0)
        return cmdversion(argc, argv);
    if (strcmp(c, "genkey") == 0)   return cmdgenkey(argc, argv);
    if (strcmp(c, "genkeypair") == 0) return cmdgenpair(argc, argv);
    if (strcmp(c, "encrypt") == 0)  return cmdencrypt(argc, argv);
    if (strcmp(c, "decrypt") == 0)  return cmddecrypt(argc, argv);
    if (strcmp(c, "inspect") == 0)  return cmdinspect(argc, argv);
    if (strcmp(c, "selftest") == 0) return cmdselftest(argc, argv);
    fprintf(stderr, "unknown command: %s\n", c);
    fprintf(stderr, "run `monolith help` for usage\n");
    return 1;
}
