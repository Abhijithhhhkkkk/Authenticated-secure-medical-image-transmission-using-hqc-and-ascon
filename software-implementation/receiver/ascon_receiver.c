/*
 * Ascon-128 v1.2 decryption wrapper
 *
 * Compatible with the older Python "ascon" package:
 *
 *     from ascon import encrypt, decrypt
 *
 * Default variant:
 *     Ascon-128
 *
 * Input:
 *     key          = 16 bytes
 *     nonce        = 16 bytes
 *     associated   = arbitrary length
 *     ciphertext   = ciphertext + 16-byte authentication tag
 *
 * Output:
 *     plaintext
 *
 * Return:
 *     0  = success
 *    -1  = authentication failure / invalid input
 *
 * Compile:
 *     gcc -O3 -fPIC -shared ascon_wrapper.c -o libascon.so
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 * Constants
 * ============================================================ */

#define ASCON_KEY_SIZE    16
#define ASCON_NONCE_SIZE  16
#define ASCON_TAG_SIZE    16

#define ASCON_RATE        8

#define ASCON_ROUNDS_A    12
#define ASCON_ROUNDS_B     6

/*
 * Ascon-128 v1.2 IV:
 *
 * rate     = 64 bits
 * key      = 128 bits
 * tag      = 128 bits
 * a        = 12
 * b        = 6
 */
#define ASCON_IV UINT64_C(0x80400c0600000000)

/* ============================================================
 * Utility functions
 * ============================================================ */

static uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

/*
 * Big-endian load.
 *
 * Ascon v1.2 uses big-endian byte interpretation.
 */
static uint64_t load64_be(const uint8_t *src)
{
    return
        ((uint64_t)src[0] << 56) |
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
    dst[6] = (uint8_t)(x >> 8);
    dst[7] = (uint8_t)x;
}

/* ============================================================
 * Ascon permutation
 * ============================================================ */

static void ascon_permutation(
    uint64_t *x0,
    uint64_t *x1,
    uint64_t *x2,
    uint64_t *x3,
    uint64_t *x4,
    int rounds)
{
    uint64_t x[5];

    x[0] = *x0;
    x[1] = *x1;
    x[2] = *x2;
    x[3] = *x3;
    x[4] = *x4;

    /*
     * Round constants for Ascon-p[12].
     *
     * Starting at 0xf0 and decreasing by 0x0f.
     */
    static const uint8_t RC[12] = {
        0xf0, 0xe1, 0xd2, 0xc3,
        0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b
    };

    int start = 12 - rounds;

    for (int r = start; r < 12; r++)
    {
        /* ----------------------------------------------------
         * Addition of round constant
         * ---------------------------------------------------- */
        x[2] ^= RC[r];

        /* ----------------------------------------------------
         * Substitution layer
         * ---------------------------------------------------- */

        x[0] ^= x[4];
        x[4] ^= x[3];
        x[2] ^= x[1];

        uint64_t t0 = ~x[0] & x[1];
        uint64_t t1 = ~x[1] & x[2];
        uint64_t t2 = ~x[2] & x[3];
        uint64_t t3 = ~x[3] & x[4];
        uint64_t t4 = ~x[4] & x[0];

        x[0] ^= t1;
        x[1] ^= t2;
        x[2] ^= t3;
        x[3] ^= t4;
        x[4] ^= t0;

        x[1] ^= x[0];
        x[0] ^= x[4];
        x[3] ^= x[2];

        x[2] = ~x[2];

        /* ----------------------------------------------------
         * Linear diffusion layer
         * ---------------------------------------------------- */

        x[0] ^= rotr64(x[0], 19) ^ rotr64(x[0], 28);
        x[1] ^= rotr64(x[1], 61) ^ rotr64(x[1], 39);
        x[2] ^= rotr64(x[2], 1)  ^ rotr64(x[2], 6);
        x[3] ^= rotr64(x[3], 10) ^ rotr64(x[3], 17);
        x[4] ^= rotr64(x[4], 7)  ^ rotr64(x[4], 41);
    }

    *x0 = x[0];
    *x1 = x[1];
    *x2 = x[2];
    *x3 = x[3];
    *x4 = x[4];
}

/* ============================================================
 * Constant-time tag comparison
 * ============================================================ */

static int constant_time_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}

/* ============================================================
 * Initialization
 * ============================================================ */

static void ascon_initialize(
    uint64_t *x0,
    uint64_t *x1,
    uint64_t *x2,
    uint64_t *x3,
    uint64_t *x4,
    const uint8_t *key,
    const uint8_t *nonce)
{
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);

    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);

    /*
     * Initial state:
     *
     * IV || K || N
     */
    *x0 = ASCON_IV;
    *x1 = k0;
    *x2 = k1;
    *x3 = n0;
    *x4 = n1;

    /* p[12] */
    ascon_permutation(
        x0, x1, x2, x3, x4,
        ASCON_ROUNDS_A
    );

    /*
     * XOR key into the state after initialization.
     */
    *x3 ^= k0;
    *x4 ^= k1;
}

/* ============================================================
 * Associated Data Processing
 * ============================================================ */

static void ascon_process_associated_data(
    uint64_t *x0,
    uint64_t *x1,
    uint64_t *x2,
    uint64_t *x3,
    uint64_t *x4,
    const uint8_t *associated_data,
    size_t associated_data_len)
{
    if (associated_data_len > 0)
    {
        size_t offset = 0;

        /*
         * Full 8-byte blocks.
         */
        while (associated_data_len - offset >= ASCON_RATE)
        {
            *x0 ^= load64_be(associated_data + offset);

            offset += ASCON_RATE;

            ascon_permutation(
                x0, x1, x2, x3, x4,
                ASCON_ROUNDS_B
            );
        }

        /*
         * Final partial block.
         *
         * 10* padding:
         *
         * message || 0x80 || 0x00...
         */
        size_t remaining = associated_data_len - offset;

        if (remaining > 0)
        {
            uint8_t block[ASCON_RATE];

            memset(block, 0, ASCON_RATE);

            memcpy(
                block,
                associated_data + offset,
                remaining
            );

            block[remaining] = 0x80;

            *x0 ^= load64_be(block);

            ascon_permutation(
                x0, x1, x2, x3, x4,
                ASCON_ROUNDS_B
            );
        }
        else
        {
            /*
             * Exact multiple of the block size:
             *
             * still process the padding block.
             */
            *x0 ^= UINT64_C(0x8000000000000000);

            ascon_permutation(
                x0, x1, x2, x3, x4,
                ASCON_ROUNDS_B
            );
        }
    }

    /*
     * Domain separation.
     */
    *x4 ^= UINT64_C(1);
}

/* ============================================================
 * Ciphertext Decryption
 * ============================================================ */

static void ascon_decrypt_data(
    uint64_t *x0,
    uint64_t *x1,
    uint64_t *x2,
    uint64_t *x3,
    uint64_t *x4,
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t ciphertext_len)
{
    size_t offset = 0;

    /*
     * Process full ciphertext blocks.
     */
    while (ciphertext_len - offset >= ASCON_RATE)
    {
        uint64_t c = load64_be(ciphertext + offset);

        /*
         * P = S0 XOR C
         */
        uint64_t p = *x0 ^ c;

        store64_be(
            plaintext + offset,
            p
        );

        /*
         * Replace S0 with ciphertext block.
         */
        *x0 = c;

        offset += ASCON_RATE;

        /*
         * p[6]
         */
        ascon_permutation(
            x0, x1, x2, x3, x4,
            ASCON_ROUNDS_B
        );
    }

    /*
     * Process final partial block.
     */
    size_t remaining = ciphertext_len - offset;

    if (remaining > 0)
    {
        uint8_t cblock[ASCON_RATE];

        memset(cblock, 0, ASCON_RATE);

        memcpy(
            cblock,
            ciphertext + offset,
            remaining
        );

        uint64_t c = load64_be(cblock);

        /*
         * P = S0 XOR C
         */
        uint64_t p = *x0 ^ c;

        uint8_t pblock[ASCON_RATE];

        store64_be(
            pblock,
            p
        );

        memcpy(
            plaintext + offset,
            pblock,
            remaining
        );

        /*
         * State update:
         *
         * S0 = C XOR padding,
         * while preserving the unused bytes.
         */
        uint64_t mask;

        if (remaining == 0)
        {
            mask = UINT64_MAX;
        }
        else
        {
            mask =
                (UINT64_C(1) <<
                 ((ASCON_RATE - remaining) * 8)) - 1;
        }

        uint64_t padding =
            UINT64_C(0x80) <<
            ((ASCON_RATE - remaining - 1) * 8);

        *x0 =
            (*x0 & mask) ^
            c ^
            padding;
    }
    else
    {
        /*
         * Empty final block:
         *
         * add 0x80 padding.
         */
        *x0 ^=
            UINT64_C(0x8000000000000000);
    }
}

/* ============================================================
 * Finalization
 * ============================================================ */

static void ascon_finalize(
    uint64_t *x0,
    uint64_t *x1,
    uint64_t *x2,
    uint64_t *x3,
    uint64_t *x4,
    const uint8_t *key,
    uint8_t *tag)
{
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);

    /*
     * Finalization:
     *
     * S2 ^= K0
     * S3 ^= K1
     * p[12]
     * S3 ^= K0
     * S4 ^= K1
     */
    *x2 ^= k0;
    *x3 ^= k1;

    ascon_permutation(
        x0, x1, x2, x3, x4,
        ASCON_ROUNDS_A
    );

    *x3 ^= k0;
    *x4 ^= k1;

    /*
     * Authentication tag = S3 || S4
     */
    store64_be(tag,      *x3);
    store64_be(tag + 8,  *x4);
}

/* ============================================================
 * Public C function
 *
 * This is the function called from Python ctypes.
 *
 * Return:
 *     0  success
 *    -1  authentication failure
 *    -2  invalid input
 * ============================================================ */

int ascon_decrypt_c(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext)
{
    /*
     * Basic input validation.
     */
    if (key == NULL ||
        nonce == NULL ||
        ciphertext == NULL ||
        plaintext == NULL)
    {
        return -2;
    }

    /*
     * Ciphertext must contain:
     *
     *     encrypted data + 16-byte tag
     */
    if (ciphertext_len < ASCON_TAG_SIZE)
    {
        return -2;
    }

    /*
     * Split:
     *
     * ciphertext_data = ciphertext[:-16]
     * received_tag    = ciphertext[-16:]
     */
    size_t encrypted_len =
        ciphertext_len - ASCON_TAG_SIZE;

    const uint8_t *received_tag =
        ciphertext + encrypted_len;

    /*
     * Ascon state.
     */
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;

    /* --------------------------------------------------------
     * Initialization
     * -------------------------------------------------------- */

    ascon_initialize(
        &x0,
        &x1,
        &x2,
        &x3,
        &x4,
        key,
        nonce
    );

    /* --------------------------------------------------------
     * Associated Data
     * -------------------------------------------------------- */

    if (associated_data_len > 0)
    {
        if (associated_data == NULL)
        {
            return -2;
        }
    }

    ascon_process_associated_data(
        &x0,
        &x1,
        &x2,
        &x3,
        &x4,
        associated_data,
        associated_data_len
    );

    /* --------------------------------------------------------
     * Decrypt ciphertext
     * -------------------------------------------------------- */

    ascon_decrypt_data(
        &x0,
        &x1,
        &x2,
        &x3,
        &x4,
        ciphertext,
        plaintext,
        encrypted_len
    );

    /* --------------------------------------------------------
     * Generate authentication tag
     * -------------------------------------------------------- */

    uint8_t calculated_tag[ASCON_TAG_SIZE];

    ascon_finalize(
        &x0,
        &x1,
        &x2,
        &x3,
        &x4,
        key,
        calculated_tag
    );

    /* --------------------------------------------------------
     * Verify authentication tag
     * -------------------------------------------------------- */

    int valid =
        constant_time_compare(
            calculated_tag,
            received_tag,
            ASCON_TAG_SIZE
        );

    /*
     * IMPORTANT:
     *
     * Do not release plaintext when authentication fails.
     */
    if (!valid)
    {
        memset(
            plaintext,
            0,
            encrypted_len
        );

        return -1;
    }

    return 0;
}

/* ============================================================
 * Optional helper
 *
 * Returns plaintext length if authentication succeeds.
 * ============================================================ */

size_t ascon_decrypt_length(
    size_t ciphertext_len)
{
    if (ciphertext_len < ASCON_TAG_SIZE)
    {
        return 0;
    }

    return ciphertext_len - ASCON_TAG_SIZE;
}