// backend/src/confidential_compute/enclave/hybrid_pqc.h
#ifndef HYBRID_PQC_H
#define HYBRID_PQC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Key sizes
#define KYBER_PK_SIZE 1568
#define KYBER_SK_SIZE 3168
#define ECDH_PK_SIZE 64
#define ECDH_SK_SIZE 32

// Struct definitions
typedef struct {
    uint8_t kyber_pk[KYBER_PK_SIZE];
    uint8_t ecdh_pk[ECDH_PK_SIZE];
} HybridPublicKey;

typedef struct {
    uint8_t kyber_ct[KYBER_PK_SIZE];
    uint8_t kyber_ss[32];
    uint8_t ecdh_ss[32];
    uint8_t aes_ct[1024];  // Variable size
    uint8_t iv[12];
    uint8_t tag[16];
} HybridCiphertext;

typedef struct {
    uint8_t public_key[KYBER_PK_SIZE];
    uint8_t private_key[KYBER_SK_SIZE];
} Kyber1024KeyPair;

typedef struct {
    uint8_t public_key[ECDH_PK_SIZE];
    uint8_t private_key[ECDH_SK_SIZE];
} ECDHKeyPair;

#ifdef __cplusplus
}
#endif

#endif // HYBRID_PQC_H