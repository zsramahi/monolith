#ifndef MONOLITH_FORMAT_H
#define MONOLITH_FORMAT_H

#include <stdint.h>

#define MONO_HEADERSIZE 24
#define MONO_MAGIC0 'M'
#define MONO_MAGIC1 'O'
#define MONO_MAGIC2 'N'
#define MONO_MAGIC3 'O'
#define MONO_VERSION 1
#define MONO_FLAG_KEM 0x01

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t nonce[16];
} monoheader;

void packheader(const monoheader *h, uint8_t out[MONO_HEADERSIZE]);
int  parseheader(const uint8_t in[MONO_HEADERSIZE], monoheader *h);

#endif
