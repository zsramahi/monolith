#ifndef MONOLITH_B64_H
#define MONOLITH_B64_H

#include <stddef.h>
#include <stdint.h>

size_t b64encsize(size_t in);
size_t b64decsize(size_t in);

void b64encode(const uint8_t *in, size_t inlen, char *out);
int  b64decode(const char *in, size_t inlen, uint8_t *out, size_t *outlen);

#endif
