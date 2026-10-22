// Build: gcc -O3 -fPIC -shared hqc_kem.c -o libhqc.so -loqs
// (add -I/path/to/liboqs/include -L/path/to/liboqs/lib if not installed system-wide)
#include <stdint.h>
#include <stddef.h>
#include <oqs/oqs.h>

static OQS_KEM *kem = NULL;

// alg: "HQC-128", "HQC-192" or "HQC-256". Returns 0 on success.
int hqc_init(const char *alg) {
    if (kem) { OQS_KEM_free(kem); kem = NULL; }
    if (!alg || !OQS_KEM_alg_is_enabled(alg)) return -1;
    kem = OQS_KEM_new(alg);
    return kem ? 0 : -2;
}

size_t hqc_public_key_size(void)    { return kem ? kem->length_public_key : 0; }
size_t hqc_secret_key_size(void)    { return kem ? kem->length_secret_key : 0; }
size_t hqc_ciphertext_size(void)    { return kem ? kem->length_ciphertext : 0; }
size_t hqc_shared_secret_size(void) { return kem ? kem->length_shared_secret : 0; }

int hqc_keypair(uint8_t *pk, uint8_t *sk) {
    if (!kem) return -1;
    return OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS ? 0 : -2;
}

int hqc_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!kem) return -1;
    return OQS_KEM_encaps(kem, ct, ss, pk) == OQS_SUCCESS ? 0 : -2;
}

int hqc_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!kem) return -1;
    return OQS_KEM_decaps(kem, ss, ct, sk) == OQS_SUCCESS ? 0 : -2;
}

void hqc_cleanse(void *buf, size_t len) { OQS_MEM_cleanse(buf, len); }

void hqc_cleanup(void) {
    if (kem) { OQS_KEM_free(kem); kem = NULL; }
}