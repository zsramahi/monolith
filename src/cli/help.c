#include <stdio.h>
#include <string.h>
#include "help.h"

#define MONOLITH_VERSION "0.1.0"

static void usagemain(void) {
    puts("monolith " MONOLITH_VERSION);
    puts("an original quantum-resistant authenticated cipher");
    puts("");
    puts("usage:");
    puts("  monolith <command> [options]");
    puts("");
    puts("commands:");
    puts("  genkey      generate a new 256-bit symmetric key");
    puts("  genkeypair  generate a new post-quantum keypair (public + private, pem)");
    puts("  encrypt     encrypt a file (--key for symmetric, --to for public-key)");
    puts("  decrypt     decrypt a .mono file (--key or --secret to match)");
    puts("  inspect     show header info for a .mono file");
    puts("  selftest    run built-in correctness tests");
    puts("  version     print version");
    puts("  help        show this message or help for a command");
    puts("");
    puts("examples:");
    puts("  monolith genkey --out my.key");
    puts("  monolith encrypt secret.txt --key my.key");
    puts("  monolith genkeypair --out-public bob.pub --out-secret bob.priv");
    puts("  monolith encrypt secret.txt --to bob.pub");
    puts("  monolith decrypt secret.txt.mono --secret bob.priv");
}

static void usagegenkey(void) {
    puts("monolith genkey [--out <file>] [--format hex|raw]");
    puts("");
    puts("  --out <file>     write key to file (default: stdout)");
    puts("  --format hex     write 64 hex characters (default)");
    puts("  --format raw     write 32 binary bytes");
}

static void usageencrypt(void) {
    puts("monolith encrypt <file> --key <keyfile|hex> [--out <file>] [--force]");
    puts("");
    puts("  <file>           plaintext input");
    puts("  --key <value>    path to a key file, or 64 hex chars inline");
    puts("  --out <file>     output path (default: <file>.mono)");
    puts("  --force          overwrite output if it exists");
}

static void usagedecrypt(void) {
    puts("monolith decrypt <file.mono> --key <keyfile|hex> [--out <file>] [--force]");
    puts("");
    puts("  <file.mono>      ciphertext input");
    puts("  --key <value>    path to a key file, or 64 hex chars inline");
    puts("  --out <file>     output path (default: input with .mono stripped)");
    puts("  --force          overwrite output if it exists");
}

static void usageinspect(void) {
    puts("monolith inspect <file.mono>");
    puts("");
    puts("  reads the header without the key and prints metadata");
}

int cmdhelp(int argc, char **argv) {
    if (argc <= 2) { usagemain(); return 0; }
    const char *t = argv[2];
    if (strcmp(t, "genkey") == 0)        usagegenkey();
    else if (strcmp(t, "encrypt") == 0)  usageencrypt();
    else if (strcmp(t, "decrypt") == 0)  usagedecrypt();
    else if (strcmp(t, "inspect") == 0)  usageinspect();
    else if (strcmp(t, "version") == 0)  puts("monolith version  print the version string");
    else if (strcmp(t, "selftest") == 0) puts("monolith selftest  run built-in correctness tests");
    else if (strcmp(t, "help") == 0)     usagemain();
    else { fprintf(stderr, "no help topic: %s\n", t); return 1; }
    return 0;
}

int cmdversion(int argc, char **argv) {
    (void)argc; (void)argv;
    puts("monolith " MONOLITH_VERSION);
    return 0;
}
