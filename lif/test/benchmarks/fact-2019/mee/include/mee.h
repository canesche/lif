#ifndef MEE_H
#define MEE_H

#include <stdint.h>
#include <openssl/sha.h>

typedef struct uint8ptr_wrapped_ty {
    uint8_t *buf;
    uint64_t len;
} uint8ptr_wrapped_ty;

typedef struct uint32ptr_wrapped_ty {
    uint32_t *buf;
    uint64_t len;
} uint32ptr_wrapped_ty;

// this should be in fact's stdlib
uint32_t bswap4(uint32_t n);

// this should be in fact's stdlib
uint16_t load16_be(uint8ptr_wrapped_ty* buf);

// this should be in fact's stdlib
void store16_be(uint8ptr_wrapped_ty* buf, uint16_t n);

typedef struct AES_KEY {
    uint32ptr_wrapped_ty* rd_key;
    uint32_t rounds;
} AES_KEY;

typedef struct {
    AES_KEY ks;
    SHA_CTX head, tail, md;
    size_t payload_length;      
    union {
        unsigned int tls_ver;
        unsigned char tls_aad[16]; 
    } aux;
} EVP_AES_HMAC_SHA1;

int32_t _aesni_cbc_hmac_sha1_cipher(
    uint8ptr_wrapped_ty* iv,
    EVP_AES_HMAC_SHA1 *key,
    uint8ptr_wrapped_ty* _out,
    uint8ptr_wrapped_ty* _in,
    uint16_t tls_ver);

void aesni_cbc_encrypt(
    uint8ptr_wrapped_ty* input,
    uint8ptr_wrapped_ty* out,
    uint64_t length,
    uint32ptr_wrapped_ty* key, // actually struct AES_KEY
    uint8ptr_wrapped_ty* iv,
    int32_t enc);

#endif