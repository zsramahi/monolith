#include <string.h>
#include "duplex.h"
#include "perm.h"
#include "../util/bytes.h"

static const uint64_t DOMAIN_HEADER = 0x484F4C494C4F4E4DULL;
static const uint64_t DOMAIN_VERSION = 0x0000000000000001ULL;

static void squeezerate(mono *m) {
    for (int j = 0; j < MONOLITH_RATELANES; j++) {
        storele(m->buf + 8 * j, m->s[j]);
    }
}

static void absorbrate(mono *m) {
    for (int j = 0; j < MONOLITH_RATELANES; j++) {
        m->s[j] = loadle(m->buf + 8 * j);
    }
}

void monoinit(mono *m, const uint8_t key[MONOLITH_KEYBYTES],
              const uint8_t nonce[MONOLITH_NONCEBYTES]) {
    m->s[0] = loadle(nonce);
    m->s[1] = loadle(nonce + 8);
    m->s[2] = DOMAIN_HEADER;
    m->s[3] = DOMAIN_VERSION;
    m->s[4] = MONOLITH_IV[0];
    m->s[5] = MONOLITH_IV[1];
    m->s[6] = MONOLITH_IV[2];
    m->s[7] = MONOLITH_IV[3];
    m->s[8]  = loadle(key);
    m->s[9]  = loadle(key + 8);
    m->s[10] = loadle(key + 16);
    m->s[11] = loadle(key + 24);
    m->s[12] = 0;
    m->s[13] = 0;
    m->s[14] = 0;
    m->s[15] = 0;

    monolithperm(m->s);
    squeezerate(m);
    m->buflen = 0;
}

void monoencrypt(mono *m, const uint8_t *in, uint8_t *out, size_t len) {
    while (len > 0) {
        if (m->buflen == MONOLITH_RATEBYTES) {
            absorbrate(m);
            monolithperm(m->s);
            squeezerate(m);
            m->buflen = 0;
        }
        size_t take = MONOLITH_RATEBYTES - m->buflen;
        if (take > len) take = len;
        for (size_t i = 0; i < take; i++) {
            uint8_t c = in[i] ^ m->buf[m->buflen + i];
            out[i] = c;
            m->buf[m->buflen + i] = c;
        }
        m->buflen += take;
        in += take;
        out += take;
        len -= take;
    }
}

void monodecrypt(mono *m, const uint8_t *in, uint8_t *out, size_t len) {
    while (len > 0) {
        if (m->buflen == MONOLITH_RATEBYTES) {
            absorbrate(m);
            monolithperm(m->s);
            squeezerate(m);
            m->buflen = 0;
        }
        size_t take = MONOLITH_RATEBYTES - m->buflen;
        if (take > len) take = len;
        for (size_t i = 0; i < take; i++) {
            uint8_t c = in[i];
            out[i] = c ^ m->buf[m->buflen + i];
            m->buf[m->buflen + i] = c;
        }
        m->buflen += take;
        in += take;
        out += take;
        len -= take;
    }
}

void monofinish(mono *m, uint8_t tag[MONOLITH_TAGBYTES]) {
    if (m->buflen == MONOLITH_RATEBYTES) {
        absorbrate(m);
        monolithperm(m->s);
        squeezerate(m);
        m->buflen = 0;
    }
    m->buf[m->buflen] ^= 0x80;
    absorbrate(m);
    m->s[15] ^= MONOLITH_DOMAIN_TAG;
    monolithperm(m->s);
    storele(tag, m->s[0]);
    storele(tag + 8, m->s[1]);
}

int monoctcompare(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 0 : -1;
}
