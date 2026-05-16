#include "rng.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000L)
#endif

int rngfill(uint8_t *buf, size_t len) {
    while (len > 0) {
        ULONG chunk = (len > 0xFFFFFF00UL) ? 0xFFFFFF00UL : (ULONG)len;
        LONG status = BCryptGenRandom(NULL, buf, chunk,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != STATUS_SUCCESS) return -1;
        buf += chunk;
        len -= chunk;
    }
    return 0;
}
