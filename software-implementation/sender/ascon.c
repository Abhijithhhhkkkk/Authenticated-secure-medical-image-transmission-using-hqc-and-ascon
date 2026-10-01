#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * ASCON-128
 *
 * Rate      : 8 bytes
 * Key       : 16 bytes
 * Nonce     : 16 bytes
 * Tag       : 16 bytes
 * a-rounds  : 12
 * b-rounds  : 6
 */

static const uint64_t ASCON_IV = 0x80400c0600000000ULL;

static uint64_t load64_be(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  |
           ((uint64_t)src[7]);
}

static void store64_be(uint8_t *dst, uint64_t x)
{
    dst[0] = (uint8_t)(x >> 56);
    dst[1] = (uint8_t)(x >> 48);
    dst[2] = (uint8_t)(x >> 40);
    dst[3] = (uint8_t)(x >> 32);
    dst[4] = (uint8_t)(x >> 24);
    dst[5] = (uint8_t)(x >> 16);
    dst[6] = (uint8_t)(x >> 8);
    dst[7] = (uint8_t)x;
}

static uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

static void ascon_round(uint64_t x[5], uint8_t round)
{
    static const uint64_t RC[12] = {
        0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL,
        0xb4ULL, 0xa5ULL, 0x96ULL, 0x87ULL,
        0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL
    };

    uint64_t x0 = x[0];
    uint64_t x1 = x[1];
    uint64_t x2 = x[2];
    uint64_t x3 = x[3];
    uint64_t x4 = x[4];

    /* Add round constant */
    x2 ^= RC[round];

    /* Substitution layer */

    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;

    uint64_t t0 = ~x0 & x1;
    uint64_t t1 = ~x1 & x2;
    uint64_t t2 = ~x2 & x3;
    uint64_t t3 = ~x3 & x4;
    uint64_t t4 = ~x4 & x0;

    x0 ^= t1;
    x1 ^= t2;
    x2 ^= t3;
    x3 ^= t4;
    x4 ^= t0;

    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2;

    /* Linear diffusion layer */

    x0 ^= rotr64(x0, 19) ^ rotr64(x0, 28);
    x1 ^= rotr64(x1, 61) ^ rotr64(x1, 39);
    x2 ^= rotr64(x2, 1)  ^ rotr64(x2, 6);
    x3 ^= rotr64(x3, 10) ^ rotr64(x3, 17);
    x4 ^= rotr64(x4, 7)  ^ rotr64(x4, 41);

    x[0] = x0;
    x[1] = x1;
    x[2] = x2;
    x[3] = x3;
    x[4] = x4;
}

static void ascon_permutation(uint64_t x[5], int rounds)
{
    int start = 12 - rounds;

    for (int i = start; i < 12; i++) {
        ascon_round(x, (uint8_t)i);
    }
}

static void pad_block(uint64_t *x0, const uint8_t *data, size_t len)
{
    uint8_t block[8] = {0};

    if (len > 0) {
        memcpy(block, data, len);
    }

    block[len] = 0x80;

    *x0 ^= load64_be(block);
}

static void absorb_associated_data(
    uint64_t x[5],
    const uint8_t *aad,
    size_t aad_len
)
{
    if (aad_len == 0) {
        return;
    }

    while (aad_len >= 8) {

        x[0] ^= load64_be(aad);

        ascon_permutation(x, 6);

        aad += 8;
        aad_len -= 8;
    }

    if (aad_len > 0) {
        pad_block(&x[0], aad, aad_len);
    } else {
        x[0] ^= 0x8000000000000000ULL;
    }

    ascon_permutation(x, 6);
}

int ascon_encrypt_c(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext
)
{
    if (key == NULL ||
        nonce == NULL ||
        plaintext == NULL ||
        ciphertext == NULL) {
        return -1;
    }

    uint64_t K0 = load64_be(key);
    uint64_t K1 = load64_be(key + 8);

    uint64_t N0 = load64_be(nonce);
    uint64_t N1 = load64_be(nonce + 8);

    uint64_t x[5];

    /*
     * Initialization
     */

    x[0] = ASCON_IV;
    x[1] = K0;
    x[2] = K1;
    x[3] = N0;
    x[4] = N1;

    ascon_permutation(x, 12);

    x[3] ^= K0;
    x[4] ^= K1;

    /*
     * Associated Data
     */

    absorb_associated_data(x, aad, aad_len);

    /*
     * Domain separation
     */

    x[4] ^= 1ULL;

    /*
     * Plaintext encryption
     */

    size_t remaining = plaintext_len;
    size_t offset = 0;

    while (remaining >= 8) {

        uint64_t block = load64_be(plaintext + offset);

        uint64_t encrypted = x[0] ^ block;

        store64_be(ciphertext + offset, encrypted);

        x[0] = encrypted;

        ascon_permutation(x, 6);

        offset += 8;
        remaining -= 8;
    }

    /*
     * Final partial block
     */

    if (remaining > 0) {

        uint8_t block[8] = {0};

        memcpy(block, plaintext + offset, remaining);

        block[remaining] = 0x80;

        uint64_t p = load64_be(block);

        uint64_t c = x[0] ^ p;

        uint8_t temp[8];

        store64_be(temp, c);

        memcpy(ciphertext + offset, temp, remaining);

        x[0] = c;

    } else {

        x[0] ^= 0x8000000000000000ULL;
    }

    /*
     * Finalization
     */

    x[2] ^= K0;
    x[3] ^= K1;

    ascon_permutation(x, 12);

    x[3] ^= K0;
    x[4] ^= K1;

    /*
     * Authentication tag
     */

    store64_be(ciphertext + plaintext_len, x[3]);
    store64_be(ciphertext + plaintext_len + 8, x[4]);

    return 0;
}