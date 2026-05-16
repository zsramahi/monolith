/*
 * keccak (sha-3 / shake) for monolith.
 * adapted from the public-domain fips202 reference by ronny van keer,
 * gilles van assche, daniel j. bernstein, and peter schwabe.
 * upstream license: cc0 / apache 2.0.
 */

#include "keccak.h"

#define ROUNDS 24
#define ROL(a, off) (((a) << (off)) ^ ((a) >> (64 - (off))))

static uint64_t load64(const uint8_t x[8]) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r |= (uint64_t)x[i] << (8 * i);
    return r;
}

static void store64(uint8_t x[8], uint64_t u) {
    for (int i = 0; i < 8; i++) x[i] = (uint8_t)(u >> (8 * i));
}

static const uint64_t RC[ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static void permute(uint64_t s[25]) {
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    Aba = s[ 0]; Abe = s[ 1]; Abi = s[ 2]; Abo = s[ 3]; Abu = s[ 4];
    Aga = s[ 5]; Age = s[ 6]; Agi = s[ 7]; Ago = s[ 8]; Agu = s[ 9];
    Aka = s[10]; Ake = s[11]; Aki = s[12]; Ako = s[13]; Aku = s[14];
    Ama = s[15]; Ame = s[16]; Ami = s[17]; Amo = s[18]; Amu = s[19];
    Asa = s[20]; Ase = s[21]; Asi = s[22]; Aso = s[23]; Asu = s[24];

    for (int round = 0; round < ROUNDS; round += 2) {
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da; BCa = Aba;
        Age ^= De; BCe = ROL(Age, 44);
        Aki ^= Di; BCi = ROL(Aki, 43);
        Amo ^= Do; BCo = ROL(Amo, 21);
        Asu ^= Du; BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= RC[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do; BCa = ROL(Abo, 28);
        Agu ^= Du; BCe = ROL(Agu, 20);
        Aka ^= Da; BCi = ROL(Aka,  3);
        Ame ^= De; BCo = ROL(Ame, 45);
        Asi ^= Di; BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De; BCa = ROL(Abe,  1);
        Agi ^= Di; BCe = ROL(Agi,  6);
        Ako ^= Do; BCi = ROL(Ako, 25);
        Amu ^= Du; BCo = ROL(Amu,  8);
        Asa ^= Da; BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du; BCa = ROL(Abu, 27);
        Aga ^= Da; BCe = ROL(Aga, 36);
        Ake ^= De; BCi = ROL(Ake, 10);
        Ami ^= Di; BCo = ROL(Ami, 15);
        Aso ^= Do; BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di; BCa = ROL(Abi, 62);
        Ago ^= Do; BCe = ROL(Ago, 55);
        Aku ^= Du; BCi = ROL(Aku, 39);
        Ama ^= Da; BCo = ROL(Ama, 41);
        Ase ^= De; BCu = ROL(Ase,  2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da; BCa = Eba;
        Ege ^= De; BCe = ROL(Ege, 44);
        Eki ^= Di; BCi = ROL(Eki, 43);
        Emo ^= Do; BCo = ROL(Emo, 21);
        Esu ^= Du; BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= RC[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do; BCa = ROL(Ebo, 28);
        Egu ^= Du; BCe = ROL(Egu, 20);
        Eka ^= Da; BCi = ROL(Eka,  3);
        Eme ^= De; BCo = ROL(Eme, 45);
        Esi ^= Di; BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De; BCa = ROL(Ebe,  1);
        Egi ^= Di; BCe = ROL(Egi,  6);
        Eko ^= Do; BCi = ROL(Eko, 25);
        Emu ^= Du; BCo = ROL(Emu,  8);
        Esa ^= Da; BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du; BCa = ROL(Ebu, 27);
        Ega ^= Da; BCe = ROL(Ega, 36);
        Eke ^= De; BCi = ROL(Eke, 10);
        Emi ^= Di; BCo = ROL(Emi, 15);
        Eso ^= Do; BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di; BCa = ROL(Ebi, 62);
        Ego ^= Do; BCe = ROL(Ego, 55);
        Eku ^= Du; BCi = ROL(Eku, 39);
        Ema ^= Da; BCo = ROL(Ema, 41);
        Ese ^= De; BCu = ROL(Ese,  2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    s[ 0] = Aba; s[ 1] = Abe; s[ 2] = Abi; s[ 3] = Abo; s[ 4] = Abu;
    s[ 5] = Aga; s[ 6] = Age; s[ 7] = Agi; s[ 8] = Ago; s[ 9] = Agu;
    s[10] = Aka; s[11] = Ake; s[12] = Aki; s[13] = Ako; s[14] = Aku;
    s[15] = Ama; s[16] = Ame; s[17] = Ami; s[18] = Amo; s[19] = Amu;
    s[20] = Asa; s[21] = Ase; s[22] = Asi; s[23] = Aso; s[24] = Asu;
}

static void absorbonce(uint64_t s[25], unsigned int r,
                       const uint8_t *in, size_t inlen, uint8_t p) {
    for (int i = 0; i < 25; i++) s[i] = 0;
    while (inlen >= r) {
        for (unsigned int i = 0; i < r / 8; i++)
            s[i] ^= load64(in + 8 * i);
        in += r;
        inlen -= r;
        permute(s);
    }
    unsigned int i;
    for (i = 0; i < inlen; i++)
        s[i / 8] ^= (uint64_t)in[i] << (8 * (i % 8));
    s[i / 8] ^= (uint64_t)p << (8 * (i % 8));
    s[(r - 1) / 8] ^= 1ULL << 63;
}

static unsigned int absorb(uint64_t s[25], unsigned int pos, unsigned int r,
                           const uint8_t *in, size_t inlen) {
    while (pos + inlen >= r) {
        for (unsigned int i = pos; i < r; i++)
            s[i / 8] ^= (uint64_t)*in++ << (8 * (i % 8));
        inlen -= r - pos;
        permute(s);
        pos = 0;
    }
    unsigned int i;
    for (i = pos; i < pos + inlen; i++)
        s[i / 8] ^= (uint64_t)*in++ << (8 * (i % 8));
    return i;
}

static void finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p) {
    s[pos / 8] ^= (uint64_t)p << (8 * (pos % 8));
    s[r / 8 - 1] ^= 1ULL << 63;
}

static unsigned int squeeze(uint8_t *out, size_t outlen, uint64_t s[25],
                            unsigned int pos, unsigned int r) {
    while (outlen) {
        if (pos == r) {
            permute(s);
            pos = 0;
        }
        unsigned int i;
        for (i = pos; i < r && i < pos + outlen; i++)
            *out++ = (uint8_t)(s[i / 8] >> (8 * (i % 8)));
        outlen -= i - pos;
        pos = i;
    }
    return pos;
}

static void squeezeblocks(uint8_t *out, size_t nblocks, uint64_t s[25], unsigned int r) {
    while (nblocks) {
        permute(s);
        for (unsigned int i = 0; i < r / 8; i++)
            store64(out + 8 * i, s[i]);
        out += r;
        nblocks -= 1;
    }
}

void shake128init(keccak *st) {
    for (int i = 0; i < 25; i++) st->s[i] = 0;
    st->pos = 0;
}

void shake128absorbonce(keccak *st, const uint8_t *in, size_t inlen) {
    absorbonce(st->s, SHAKE128RATE, in, inlen, 0x1F);
    st->pos = SHAKE128RATE;
}

void shake128squeezeblocks(uint8_t *out, size_t nblocks, keccak *st) {
    squeezeblocks(out, nblocks, st->s, SHAKE128RATE);
}

void shake256init(keccak *st) {
    for (int i = 0; i < 25; i++) st->s[i] = 0;
    st->pos = 0;
}

void shake256absorb(keccak *st, const uint8_t *in, size_t inlen) {
    st->pos = absorb(st->s, st->pos, SHAKE256RATE, in, inlen);
}

void shake256finalize(keccak *st) {
    finalize(st->s, st->pos, SHAKE256RATE, 0x1F);
    st->pos = SHAKE256RATE;
}

void shake256squeeze(uint8_t *out, size_t outlen, keccak *st) {
    st->pos = squeeze(out, outlen, st->s, st->pos, SHAKE256RATE);
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak st;
    absorbonce(st.s, SHAKE256RATE, in, inlen, 0x1F);
    size_t nblocks = outlen / SHAKE256RATE;
    squeezeblocks(out, nblocks, st.s, SHAKE256RATE);
    outlen -= nblocks * SHAKE256RATE;
    out += nblocks * SHAKE256RATE;
    st.pos = SHAKE256RATE;
    squeeze(out, outlen, st.s, st.pos, SHAKE256RATE);
}

void sha3256(uint8_t h[32], const uint8_t *in, size_t inlen) {
    uint64_t s[25];
    absorbonce(s, SHA3256RATE, in, inlen, 0x06);
    permute(s);
    for (int i = 0; i < 4; i++) store64(h + 8 * i, s[i]);
}

void sha3512(uint8_t h[64], const uint8_t *in, size_t inlen) {
    uint64_t s[25];
    absorbonce(s, SHA3512RATE, in, inlen, 0x06);
    permute(s);
    for (int i = 0; i < 8; i++) store64(h + 8 * i, s[i]);
}
