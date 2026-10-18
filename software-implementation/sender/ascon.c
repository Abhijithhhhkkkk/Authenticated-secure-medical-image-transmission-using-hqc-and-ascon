/*
 * Ascon-128 (v1.2) - encrypt + decrypt in one library
 *
 * Compile:
 *     gcc -O3 -fPIC -shared ascon_wrapper.c -o libascon.so
 *
 * Exported functions (called from Python via ctypes):
 *
 *   int ascon_encrypt_c(key, nonce, aad, aad_len,
 *                       plaintext, plaintext_len,
 *                       ciphertext);        // plaintext_len + 16 bytes out
 *
 *   int ascon_decrypt_c(key, nonce, aad, aad_len,
 *                       ciphertext, ciphertext_len,   // includes 16-byte tag
 *                       plaintext);         // ciphertext_len - 16 bytes out
 *
 * Return values:
 *      0  success
 *     -1  authentication failure (decrypt only; plaintext is zeroed)
 *     -2  invalid input
 *
 * Key = 16 bytes, Nonce = 16 bytes, Tag = 16 bytes, rate = 8 bytes,
 * a-rounds = 12, b-rounds = 6.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 * Constants
 * ============================================================ */

#define ASCON_RATE      8
#define ASCON_TAG_SIZE  16
#define ASCON_ROUNDS_A  12
#define ASCON_ROUNDS_B  6

#define ASCON_IV UINT64_C(0x80400c0600000000)
#define ASCON_PAD_FULL UINT64_C(0x8000000000000000)

/* ============================================================
 * Utilities
 * ============================================================ */

static uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t load64_be(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] <<  8) |
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
    dst[6] = (uint8_t)(x >>  8);
    dst[7] = (uint8_t)x;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0;
}

/* ============================================================
 * Permutation
 * ============================================================ */

static void ascon_permutation(uint64_t s[5], int rounds)
{
    static const uint8_t RC[12] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
        0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };

    uint64_t x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4];

    for (int r = 12 - rounds; r < 12; r++) {

        /* Round constant */
        x2 ^= RC[r];

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
        x2 ^= rotr64(x2,  1) ^ rotr64(x2,  6);
        x3 ^= rotr64(x3, 10) ^ rotr64(x3, 17);
        x4 ^= rotr64(x4,  7) ^ rotr64(x4, 41);
    }

    s[0] = x0; s[1] = x1; s[2] = x2; s[3] = x3; s[4] = x4;
}

/* ============================================================
 * Shared phases (identical for encryption and decryption)
 * ============================================================ */

static void ascon_initialize(uint64_t s[5],
                             const uint8_t *key,
                             const uint8_t *nonce)
{
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);

    s[0] = ASCON_IV;
    s[1] = k0;
    s[2] = k1;
    s[3] = load64_be(nonce);
    s[4] = load64_be(nonce + 8);

    ascon_permutation(s, ASCON_ROUNDS_A);

    s[3] ^= k0;
    s[4] ^= k1;
}

static void ascon_absorb_ad(uint64_t s[5],
                            const uint8_t *ad,
                            size_t ad_len)
{
    if (ad_len > 0) {

        while (ad_len >= ASCON_RATE) {
            s[0] ^= load64_be(ad);
            ascon_permutation(s, ASCON_ROUNDS_B);
            ad += ASCON_RATE;
            ad_len -= ASCON_RATE;
        }

        if (ad_len > 0) {
            uint8_t block[ASCON_RATE] = {0};
            memcpy(block, ad, ad_len);
            block[ad_len] = 0x80;
            s[0] ^= load64_be(block);
        } else {
            s[0] ^= ASCON_PAD_FULL;
        }

        ascon_permutation(s, ASCON_ROUNDS_B);
    }

    /* Domain separation */
    s[4] ^= UINT64_C(1);
}

static void ascon_finalize(uint64_t s[5],
                           const uint8_t *key,
                           uint8_t tag[ASCON_TAG_SIZE])
{
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);

    s[1] ^= k0;
    s[2] ^= k1;

    ascon_permutation(s, ASCON_ROUNDS_A);

    s[3] ^= k0;
    s[4] ^= k1;

    store64_be(tag,     s[3]);
    store64_be(tag + 8, s[4]);
}

/* ============================================================
 * ENCRYPT
 * ============================================================ */

int ascon_encrypt_c(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext)
{
    if (key == NULL || nonce == NULL || ciphertext == NULL ||
        (aad_len > 0 && aad == NULL) ||
        (plaintext_len > 0 && plaintext == NULL)) {
        return -2;
    }

    uint64_t s[5];

    ascon_initialize(s, key, nonce);
    ascon_absorb_ad(s, aad, aad_len);

    size_t offset = 0;

    /* Full blocks */
    while (plaintext_len - offset >= ASCON_RATE) {
        s[0] ^= load64_be(plaintext + offset);
        store64_be(ciphertext + offset, s[0]);
        ascon_permutation(s, ASCON_ROUNDS_B);
        offset += ASCON_RATE;
    }

    /* Final block (always padded, even when empty) */
    size_t rem = plaintext_len - offset;

    if (rem > 0) {
        uint8_t block[ASCON_RATE] = {0};
        memcpy(block, plaintext + offset, rem);
        block[rem] = 0x80;

        s[0] ^= load64_be(block);

        store64_be(block, s[0]);
        memcpy(ciphertext + offset, block, rem);
    } else {
        s[0] ^= ASCON_PAD_FULL;
    }

    ascon_finalize(s, key, ciphertext + plaintext_len);

    return 0;
}

/* ============================================================
 * DECRYPT
 * ============================================================ */

int ascon_decrypt_c(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext)
{
    if (key == NULL || nonce == NULL || ciphertext == NULL ||
        ciphertext_len < ASCON_TAG_SIZE ||
        (aad_len > 0 && aad == NULL)) {
        return -2;
    }

    size_t data_len = ciphertext_len - ASCON_TAG_SIZE;

    if (data_len > 0 && plaintext == NULL) {
        return -2;
    }

    uint64_t s[5];

    ascon_initialize(s, key, nonce);
    ascon_absorb_ad(s, aad, aad_len);

    size_t offset = 0;

    /* Full blocks */
    while (data_len - offset >= ASCON_RATE) {
        uint64_t c = load64_be(ciphertext + offset);
        store64_be(plaintext + offset, s[0] ^ c);
        s[0] = c;
        ascon_permutation(s, ASCON_ROUNDS_B);
        offset += ASCON_RATE;
    }

    /* Final block */
    size_t rem = data_len - offset;

    if (rem > 0) {
        uint8_t state_bytes[ASCON_RATE];
        store64_be(state_bytes, s[0]);

        for (size_t i = 0; i < rem; i++) {
            uint8_t c = ciphertext[offset + i];
            plaintext[offset + i] = (uint8_t)(state_bytes[i] ^ c);
            state_bytes[i] = c;
        }

        state_bytes[rem] ^= 0x80;
        s[0] = load64_be(state_bytes);
    } else {
        s[0] ^= ASCON_PAD_FULL;
    }

    uint8_t tag[ASCON_TAG_SIZE];
    ascon_finalize(s, key, tag);

    if (!constant_time_equal(tag, ciphertext + data_len, ASCON_TAG_SIZE)) {
        if (data_len > 0) {
            memset(plaintext, 0, data_len);
        }
        return -1;
    }

    return 0;
}