#ifndef MONOLITH_INDCPA_H
#define MONOLITH_INDCPA_H

#include <stdint.h>
#include "params.h"

void indcpakeypair(uint8_t pk[KEMINDCPAPUBKEYBYTES],
                   uint8_t sk[KEMINDCPASECKEYBYTES],
                   const uint8_t coins[KEMSYMBYTES]);

void indcpaenc(uint8_t c[KEMINDCPACTBYTES],
               const uint8_t m[KEMINDCPAMSGBYTES],
               const uint8_t pk[KEMINDCPAPUBKEYBYTES],
               const uint8_t coins[KEMSYMBYTES]);

void indcpadec(uint8_t m[KEMINDCPAMSGBYTES],
               const uint8_t c[KEMINDCPACTBYTES],
               const uint8_t sk[KEMINDCPASECKEYBYTES]);

#endif
