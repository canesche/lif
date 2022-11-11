#ifndef CRYPTO_SECRETBOX_H
#define CRYPTO_SECRETBOX_H

#include <stdint.h>

typedef struct uint8ptr_wrapped_ty {
    uint8_t *buf;
    uint64_t len;
} uint8ptr_wrapped_ty;

void _crypto_core_hsalsa20(
    uint8ptr_wrapped_ty* out,
    uint8ptr_wrapped_ty* input,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_stream_xsalsa20(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_stream_xsalsa20_xor_ic(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint64_t ic,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_stream_xsalsa20_xor(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_secretbox_xsalsa20poly1305(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_secretbox_xsalsa20poly1305_open(
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_secretbox(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k);

int32_t _crypto_secretbox_open(
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k); 

#endif