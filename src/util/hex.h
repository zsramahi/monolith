#ifndef MONOLITH_HEX_H
#define MONOLITH_HEX_H

#include <stddef.h>
#include <stdint.h>

void hexencode(const uint8_t *in, size_t len, char *out);
int hexdecode(const char *in, size_t len, uint8_t *out);

#endif
