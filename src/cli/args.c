#include <string.h>
#include <stdio.h>
#include "args.h"

void argsinit(cliargs *a) {
    a->input = NULL;
    a->out = NULL;
    a->key = NULL;
    a->format = NULL;
    a->force = 0;
    a->errflag = 0;
    a->errmsg = NULL;
}

static int needsval(cliargs *a, int i, int argc, const char *flag) {
    if (i + 1 >= argc) {
        a->errflag = 1;
        a->errmsg = flag;
        return 0;
    }
    return 1;
}

int argsparse(cliargs *a, int argc, char **argv, int from) {
    for (int i = from; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "--key") == 0) {
            if (!needsval(a, i, argc, "--key")) return -1;
            a->key = argv[++i];
        } else if (strcmp(s, "--out") == 0 || strcmp(s, "-o") == 0) {
            if (!needsval(a, i, argc, "--out")) return -1;
            a->out = argv[++i];
        } else if (strcmp(s, "--format") == 0) {
            if (!needsval(a, i, argc, "--format")) return -1;
            a->format = argv[++i];
        } else if (strcmp(s, "--force") == 0 || strcmp(s, "-f") == 0) {
            a->force = 1;
        } else if (s[0] == '-' && s[1] != '\0') {
            a->errflag = 1;
            a->errmsg = s;
            return -1;
        } else {
            if (a->input != NULL) {
                a->errflag = 1;
                a->errmsg = s;
                return -1;
            }
            a->input = s;
        }
    }
    return 0;
}
