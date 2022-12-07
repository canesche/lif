

/**
 * Port from FaCT implementation:
 * https://github.com/PLSysSec/fact-eval/blob/master/openssl-mee/20170717_latest.fact
 */

#include "../include/mee.h"
#include "../../../include/taint.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <crypt.h>
//#include <openssl/aes.h>

# define l2n(l,c) (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                   *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                   *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                   *((c)++)=(unsigned char)(((l)    )&0xff))

uint64_t load_limb(uint8_t *input) {
    return
        ((uint64_t)  input[0])        |
        (((uint64_t) input[1]) << 8)  |
        (((uint64_t) input[2]) << 16) |
        (((uint64_t) input[3]) << 24) |
        (((uint64_t) input[4]) << 32) |
        (((uint64_t) input[5]) << 40) |
        (((uint64_t) input[6]) << 48) |
        (((uint64_t) input[7]) << 56);
}

void memzero(uint8ptr_wrapped_ty* buf) {
  for (int i = 0; i < buf->len; ++i) {
    buf->buf[i] = 0;
  }
}

const void * view(uint8_t* input, uint32_t s_in, uint32_t s_out) {
  uint8_t view[8];

  if (s_in == 0) {
    memcpy(view, input, 8);
  } else {
    memcpy(view, &input[s_in], 8);
  }

  return view;
}

uint32_t bswap4(uint32_t n) {
  uint32_t x4 = ((n >> 0 ) & 0xFF) << 24;
  uint32_t x3 = ((n >> 8 ) & 0xFF) << 16;
  uint32_t x2 = ((n >> 16) & 0xFF) << 8 ;
  uint32_t x1 = ((n >> 24) & 0xFF) << 0 ;
  return x1 | x2 | x3 | x4;
}

uint16_t load16_be(uint8ptr_wrapped_ty* buf) {
  uint16_t x2 = (buf->buf[0]) << 8 ;
  uint16_t x1 = (buf->buf[1]);
  return x1 | x2;
}

void store16_be(uint8ptr_wrapped_ty* buf, uint16_t n) {
  buf->len = 2;
  buf->buf[0] = (n >> 8);
  buf->buf[1] = (n);
}

void store_le(uint8ptr_wrapped_ty* buf, uint16_t n) {
  buf->len = 2;
  buf->buf[0] = (n);
  buf->buf[1] = (n >> 8);
}

uint64_t load_le(uint64_t value) {
  return value;
}

static void md_final_raw(SHA_CTX *ctx, unsigned char *md_out) {
    l2n(ctx->h0, md_out);
    l2n(ctx->h1, md_out);
    l2n(ctx->h2, md_out);
    l2n(ctx->h3, md_out);
    l2n(ctx->h4, md_out);
}

// TODO: I didn't find this function
void sha1_block_data_order (SHA_CTX *c, const void *p, size_t num) {
    return;
}

void _sha1_update(struct SHA_CTX *c, const void *data, size_t len) {
  SHA1_Update(c, data, len);
}

int32_t _aesni_cbc_hmac_sha1_cipher(
    uint8ptr_wrapped_ty* iv,
    EVP_AES_HMAC_SHA1 *key,
    uint8ptr_wrapped_ty* _out,
    uint8ptr_wrapped_ty* _in,
    uint16_t tls_ver) {

  //assume(len _in >= len iv);
  assert(_in->len >= iv->len);
  //assume(len _in == len _out);
  assert(_in->len == _out->len);

  uint64_t plen = 13;

  uint64_t NO_PAYLOAD_LENGTH = -1;
  uint32_t AES_BLOCK_SIZE = 16;
  //uint32_t SHA_DIGEST_LENGTH = 20;
  uint32_t TLS1_1_VERSION = 0x0302;
  //uint32_t SHA_LBLOCK = 16;
  //uint32_t SHA_CBLOCK = (SHA_LBLOCK*4); // SHA treats input data as a
                                          // contiguous array of 32 bit wide
                                          // big-endian values. 

  uint32_t inp = 0;
  uint32_t outp = 0;
  uint32_t _len = _out->len;

  //assume(inp + _len == len _in);
  //assert(inp + _len == _in->len);
  //assume(outp + _len == len _out);
  //assert(outp + _len == _out->len);
  //assume(inp + _len >= inp);
  //assert(inp + _len >= inp);
  //assume(outp + _len >= inp);
  //assert(outp + _len >= inp);

  uint32_t ret = 1;

  if (tls_ver >= TLS1_1_VERSION) { // this one is bug due to optimizer/verify interaction
    if (_len < (AES_BLOCK_SIZE + SHA_DIGEST_LENGTH + 1)) {
      return 0;
    }

    memcpy(iv, _in, iv->len);
    inp += AES_BLOCK_SIZE;
    outp += AES_BLOCK_SIZE;
    _len -= AES_BLOCK_SIZE;
  } else if (_len < (SHA_DIGEST_LENGTH + 1)) {
    return 0;
  }

  // decrypt HMAC|padding at once 
  AES_cbc_encrypt(_in, _out, _len, &key->ks.rd_key, iv, 0);

  // figure out payload length 
  uint64_t pad = _out->len-1;

  uint32_t tmppad = _len - (SHA_DIGEST_LENGTH + 1);
  uint32_t maxpad = tmppad > 255 ? 255 : tmppad;

  if (pad > maxpad) {
     // If pad is invalid then we will fail the above test but we must
     // continue anyway because we are in constant time code. However,
     // we'll use the maxpad value instead of the supplied pad to make
     // sure we perform well defined pointer arithmetic.
    pad = maxpad;
    ret = 0;
  }

   
  uint32_t inp_len = _len - (SHA_DIGEST_LENGTH + pad + 1);

  // deu ruim
  store16_be(view(key->aux.tls_aad, plen - 2, 2), (inp_len));

  // calculate HMAC 
  memcpy(key->md.data, key->head.data, key->head.num);

  _sha1_update(key->md.h0, view(key->aux.tls_aad, 0, plen), plen);

  // begin post-lucky-13 section 
  _len -= SHA_DIGEST_LENGTH; // amend mac 
  if (_len >= (256 + SHA_CBLOCK)) {
    uint32_t j = ((_len - (256 + SHA_CBLOCK)) & (0 - SHA_CBLOCK))
      + SHA_CBLOCK - key->md.num;
    //assume(j <= _len);
    _sha1_update(key->md.h0, view(_out, outp, j), j);
    outp += j;
    _len -= j;
    inp_len -= j;
  }

  // but pretend as if we hashed padded payload 
  uint32_t bitlen = bswap4(key->md.Nl + (inp_len << 3)); // at most 18 bits 

  // NOTE: openssl spends extra time aligning this to a 32-byte boundary
  uint8_t pmac[20] = {0}; // SHA_DIGEST_LENGTH

  uint32_t p_res = key->md.num;
  for (uint32_t j = 0; j < _len; j++) {
    //assume(p_res < len key.md.data);
    key->md.data[p_res] = j  < inp_len ? _out->buf[outp + j] : j == inp_len ? 0x80 : 0;
    p_res += 1;

    if (p_res == SHA_CBLOCK) {
      // j is not incremented yet 
      secret bool m1 = inp_len + 7 < j;
      if (m1) {
        store_le(view(key->md.data, 4*(SHA_LBLOCK - 1), 4), bitlen);
      }
      sha1_block_data_order(&key->md, key->md.data, 1);
      if (m1 && (j < inp_len + 72)) {
        store_le(view(pmac, 0 , 4), key->md.h0);
        store_le(view(pmac, 4 , 4), key->md.h1);
        store_le(view(pmac, 8 , 4), key->md.h2);
        store_le(view(pmac, 12, 4), key->md.h3);
        store_le(view(pmac, 16, 4), key->md.h4);
      }
      p_res = 0;
    }
  }
  uint32_t j = _len;

  for (uint32_t i = p_res; i < SHA_CBLOCK; i++) {
    key->md.data[i] = 0;
    j += 1;
  }

  if (p_res > SHA_CBLOCK - 8) {
    secret bool m1 = inp_len + 8 < j;
    if (m1) {
      store_le(view(key->md.data, 4*(SHA_LBLOCK - 1), 4), bitlen);
    }
    sha1_block_data_order(&key->md, key->md.data, 1);
    if (m1 && (j < inp_len + 73)) {
      store_le(view(pmac, 0 , 4), key->md.h0);
      store_le(view(pmac, 4 , 4), key->md.h1);
      store_le(view(pmac, 8 , 4), key->md.h2);
      store_le(view(pmac, 12, 4), key->md.h3);
      store_le(view(pmac, 16, 4), key->md.h4);
    }

    memzero(key->md.data);
    j += 64;
  }
  // NOTE: block is purely because I don't want to rename `mask`
  store_le(view(key->md.data, 4*(SHA_LBLOCK - 1), 4), bitlen);
  sha1_block_data_order(&key->md, key->md.data, 1);
  if(j < inp_len + 73) {
    store_le(view(pmac, 0 , 4), key->md.h0);
    store_le(view(pmac, 4 , 4), key->md.h1);
    store_le(view(pmac, 8 , 4), key->md.h2);
    store_le(view(pmac, 12, 4), key->md.h3);
    store_le(view(pmac, 16, 4), key->md.h4);
  }

  store_le(view(pmac, 0 , 4), bswap4(load_le(view(pmac, 0 , 4))));
  store_le(view(pmac, 4 , 4), bswap4(load_le(view(pmac, 4 , 4))));
  store_le(view(pmac, 8 , 4), bswap4(load_le(view(pmac, 8 , 4))));
  store_le(view(pmac, 12, 4), bswap4(load_le(view(pmac, 12, 4))));
  store_le(view(pmac, 16, 4), bswap4(load_le(view(pmac, 16, 4))));
  _len += SHA_DIGEST_LENGTH;
  // end post-lucky-13 section 

  memcpy(key->md.data, key->tail.data, key->md.num);
  _sha1_update(key->md.h0, pmac, 20);
  SHA1_Final(pmac, key->md.h0);

  // verify HMAC 
  uint64_t s_outp = outp + inp_len;
  // begin post-lucky-13 section 
  uint64_t p_outp = _out->len - 1 - maxpad - SHA_DIGEST_LENGTH;

  uint32_t i = 0;
  for (uint32_t j = 0; j < maxpad + SHA_DIGEST_LENGTH; j++) {
    //assume(p_outp + j < _out->len);
    uint32_t c = _out->buf[p_outp + j];
    if (p_outp + j >= s_outp + SHA_DIGEST_LENGTH) {
      if(c != pad) { // ... and padding
        ret = 0;
      }
    } else if (p_outp + j >= s_outp) {
      //assume(i < len pmac);
      if (c != pmac[(i)]/*pmac[declassify(i)]*/) { // XXX okay (see below)
        ret = 0;
      }
      i += 1;
    }
    //
    // XXX the length of pmac is 20 bytes.
    // XXX in the OpenSSL C implementation, they do some voodoo
    // XXX to ensure that pmac is 32-byte aligned.
    // XXX therefore, pmac resides entirely within an
    // XXX aligned 32-byte block.
    // XXX if cache lines are (at least) 32 bytes long,
    // XXX then the entirety of pmac will reside within
    // XXX a single cache line, and should thus be immune
    // XXX from cache timing attacks.
    //
  }

  // end post-lucky-13 section 

  return ret;
}