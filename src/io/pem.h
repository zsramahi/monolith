#ifndef MONOLITH_PEM_H
#define MONOLITH_PEM_H

#include <stddef.h>
#include <stdint.h>

int pemwrite(const char *path, const char *label, const uint8_t *data, size_t len, int force);
int pemread(const char *path, const char *label, uint8_t *out, size_t outcap, size_t *outlen);

#endif
