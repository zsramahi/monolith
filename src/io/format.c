#include <string.h>
#include "format.h"

void packheader(const monoheader *h, uint8_t out[MONO_HEADERSIZE]) {
    out[0] = MONO_MAGIC0;
    out[1] = MONO_MAGIC1;
    out[2] = MONO_MAGIC2;
    out[3] = MONO_MAGIC3;
    out[4] = h->version;
    out[5] = h->flags;
    out[6] = 0;
    out[7] = 0;
    memcpy(out + 8, h->nonce, 16);
}

int parseheader(const uint8_t in[MONO_HEADERSIZE], monoheader *h) {
    if (in[0] != MONO_MAGIC0 || in[1] != MONO_MAGIC1
     || in[2] != MONO_MAGIC2 || in[3] != MONO_MAGIC3) return -1;
    h->version = in[4];
    h->flags   = in[5];
    if (h->version != MONO_VERSION) return -2;
    if (in[6] != 0 || in[7] != 0)   return -3;
    memcpy(h->nonce, in + 8, 16);
    return 0;
}
