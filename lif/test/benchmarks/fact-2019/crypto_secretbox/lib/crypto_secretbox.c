/**
 * Port from FaCT implementation:
 * https://github.com/PLSysSec/fact-eval/blob/master/openssl-ssl3/s3_cbc.fact
 */

#include "../include/crypto_secretbox.h"
#include "../../../include/taint.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

// NOTE: the original function has an additional parameter
// `const unsigned char *c`, but the secretbox code passes
// NULL in for this parameter so I'm just not using it
void _crypto_core_hsalsa20(
    uint8ptr_wrapped_ty* out,
    uint8ptr_wrapped_ty* input,
    uint8ptr_wrapped_ty* k) {

    uint32_t x0 = 0x61707865;
    uint32_t x5 = 0x3320646e;
    uint32_t x10 = 0x79622d32;
    uint32_t x15 = 0x6b206574;

    uint32_t x1 = load_le(view(k, 0, 4));
    uint32_t x2 = load_le(view(k, 4, 4));
    uint32_t x3 = load_le(view(k, 8, 4));
    uint32_t x4 = load_le(view(k, 12, 4));
    uint32_t x11 = load_le(view(k, 16, 4));
    uint32_t x12 = load_le(view(k, 20, 4));
    uint32_t x13 = load_le(view(k, 24, 4));
    uint32_t x14 = load_le(view(k, 28, 4));
    uint32_t x6 = load_le(view(input, 0, 4));
    uint32_t x7 = load_le(view(input, 4, 4));
    uint32_t x8 = load_le(view(input, 8, 4));
    uint32_t x9 = load_le(view(input, 12, 4));

    for (uint32_t i = 0; i < 10; ++i) {
        x4  ^= (x0  + x12) <<  7 ;
        x8  ^= (x4  + x0 ) <<  9 ;
        x12 ^= (x8  + x4 ) <<  13;
        x0  ^= (x12 + x8 ) <<  18;
        x9  ^= (x5  + x1 ) <<  7 ;
        x13 ^= (x9  + x5 ) <<  9 ;
        x1  ^= (x13 + x9 ) <<  13;
        x5  ^= (x1  + x13) <<  18;
        x14 ^= (x10 + x6 ) <<  7 ;
        x2  ^= (x14 + x10) <<  9 ;
        x6  ^= (x2  + x14) <<  13;
        x10 ^= (x6  + x2 ) <<  18;
        x3  ^= (x15 + x11) <<  7 ;
        x7  ^= (x3  + x15) <<  9 ;
        x11 ^= (x7  + x3 ) <<  13;
        x15 ^= (x11 + x7 ) <<  18;
        x1  ^= (x0  + x3 ) <<  7 ;
        x2  ^= (x1  + x0 ) <<  9 ;
        x3  ^= (x2  + x1 ) <<  13;
        x0  ^= (x3  + x2 ) <<  18;
        x6  ^= (x5  + x4 ) <<  7 ;
        x7  ^= (x6  + x5 ) <<  9 ;
        x4  ^= (x7  + x6 ) <<  13;
        x5  ^= (x4  + x7 ) <<  18;
        x11 ^= (x10 + x9 ) <<  7 ;
        x8  ^= (x11 + x10) <<  9 ;
        x9  ^= (x8  + x11) <<  13;
        x10 ^= (x9  + x8 ) <<  18;
        x12 ^= (x15 + x14) <<  7 ;
        x13 ^= (x12 + x15) <<  9 ;
        x14 ^= (x13 + x12) <<  13;
        x15 ^= (x14 + x13) <<  18;
    }

    store_le(view(out, 0, 4), x0);
    store_le(view(out, 4, 4), x5);
    store_le(view(out, 8, 4), x10);
    store_le(view(out, 12, 4), x15);
    store_le(view(out, 16, 4), x6);
    store_le(view(out, 20, 4), x7);
    store_le(view(out, 24, 4), x8);
    store_le(view(out, 28, 4), x9);
}

int32_t _crypto_stream_xsalsa20(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {

  uint8_t subkey[32] = {0};
  _crypto_core_hsalsa20(subkey, view(n, 0, 16), k);
  int32_t ret = _crypto_stream_salsa20(c, view(n, 16, 8), subkey);
  smemzero(subkey);
  return ret;
}

int32_t _crypto_stream_xsalsa20_xor_ic(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint64_t ic,
    uint8ptr_wrapped_ty* k) {
  uint8_t subkey[32] = {0};
  _crypto_core_hsalsa20(subkey, view(n, 0, 16), k);
  uint8ptr_wrapped_ty* tmp = view(n, 16, 8);
  int32_t ret = _crypto_stream_salsa20_xor_ic(c, m, tmp, ic, subkey);
  smemzero(subkey);
  return ret;
}

int32_t _crypto_stream_xsalsa20_xor(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {
  return _crypto_stream_xsalsa20_xor_ic(c, m, n, 0, k);
}

int32_t _crypto_secretbox_xsalsa20poly1305(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {
  if (m->len < 32) {
    return false;
  }
  //assume(len c == len m);

  _crypto_stream_xsalsa20_xor(c, m, n, k);
  uint8ptr_wrapped_ty* cview = view(c, 16, 16);
  uint8ptr_wrapped_ty* mview = view(c, 32, c->len - 32); // yes this is c and not m
  uint8ptr_wrapped_ty* kview = view(c, 0, 32); // yes this is c and not k
  _crypto_onetimeauth_poly1305(cview, mview, kview);

  for (uint64_t i = 0; i < 16; ++i) {
    c->buf[i] = 0;
  }
  return true;
}

int32_t _crypto_secretbox_xsalsa20poly1305_open(
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {
  if (c->len < 32) {
    return false;
  }
  //assume(len c == len m);

  uint8_t subkey[32] = {0};
  _crypto_stream_xsalsa20(subkey, n, k);
  uint8ptr_wrapped_ty* tmp1 = view(c, 16, 16);
  uint8ptr_wrapped_ty* cview = view(c, 32, c->len - 32);
  if (!_crypto_onetimeauth_poly1305_verify(tmp1, cview, subkey)) {
    return false;
  }
  _crypto_stream_xsalsa20_xor(m, c, n, k);
  for (uint32_t i = 0; i < 32; ++i) {
    m->buf[i] = 0;
  }

  return true;
}

int32_t _crypto_secretbox(
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {
  return _crypto_secretbox_xsalsa20poly1305(c, m, n, k);
}

int32_t _crypto_secretbox_open(
    uint8ptr_wrapped_ty* m,
    uint8ptr_wrapped_ty* c,
    uint8ptr_wrapped_ty* n,
    uint8ptr_wrapped_ty* k) {
  return _crypto_secretbox_xsalsa20poly1305_open(m, c, n, k);
}