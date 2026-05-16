#ifndef MONOLITH_ARGS_H
#define MONOLITH_ARGS_H

#include <stdint.h>

typedef struct {
    const char *input;
    const char *out;
    const char *key;
    const char *format;
    int force;
    int errflag;
    const char *errmsg;
} cliargs;

void argsinit(cliargs *a);
int  argsparse(cliargs *a, int argc, char **argv, int from);

#endif
