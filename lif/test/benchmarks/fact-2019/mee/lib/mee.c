

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

# define l2n(l,c) (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                   *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                   *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                   *((c)++)=(unsigned char)(((l)    )&0xff))


//extern void sha1_block_data_order(SHA_CTX ctx, uint8ptr_wrapped_ty* p, uint32_t num);

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

uint64_t view(uint8_t data, uint8_t data_out, uint8_t size) {
  uint8_t view[8];
  memcpy(view, data, 8);
  return load_limb(view);
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
  store16_be(buf, n);
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

int32_t _aesni_cbc_hmac_sha1_cipher(
    uint8ptr_wrapped_ty* iv,
    EVP_AES_HMAC_SHA1 key,
    uint8ptr_wrapped_ty* _out,
    uint8ptr_wrapped_ty* _in,
    uint16_t tls_ver) {

  //assume(len _in >= len iv);
  //assume(len _in == len _out);

  uint64_t plen = 13;

  uint64_t NO_PAYLOAD_LENGTH = -1;
  uint32_t AES_BLOCK_SIZE = 16;
  uint32_t SHA_DIGEST_LENGTH_ = 20;
  uint32_t TLS1_1_VERSION = 0x0302;
  uint32_t SHA_LBLOCK_ = 16;
  uint32_t SHA_CBLOCK_ = (SHA_LBLOCK_*4); /* SHA treats input data as a
                                              * contiguous array of 32 bit wide
                                              * big-endian values. */
  
  uint32_t inp = 0;
  uint32_t outp = 0;
  uint32_t _len = _out->len; //uint32(len _out);
  
  //assume(inp + _len == len _in);
  //assume(outp + _len == len _out);
  //assume(inp + _len >= inp);
  //assume(outp + _len >= inp);

  uint32_t ret = 1;

  uint8_t view_in[8];
  uint8_t view_out[8];

  if (tls_ver >= TLS1_1_VERSION) { // this one is bug due to optimizer/verify interaction
    if (_len < (AES_BLOCK_SIZE + SHA_DIGEST_LENGTH_ + 1)) {
      return 0;
    }

    memcpy(view_in, _in->buf, 8);

    /* omit explicit iv */
    memcpy(iv, load_limb(view_in), iv->len);
    inp += AES_BLOCK_SIZE;
    outp += AES_BLOCK_SIZE;
    _len -= AES_BLOCK_SIZE;
  } else if (_len < (SHA_DIGEST_LENGTH_ + 1)) {
    return 0;
  }

  memcpy(view_in, _in->buf, 8);
  memcpy(view_out, _out->buf, 8);

  /* decrypt HMAC|padding at once */
  //aesni_cbc_encrypt(load_limb(view_in), load_limb(view_out), _len, key.ks.rd_key.buf, iv, 0);

  /* figure out payload length */
  uint32_t pad = _out->buf[_out->len - 1];
  uint32_t tmppad = _len - (SHA_DIGEST_LENGTH_ + 1);
  uint32_t maxpad = tmppad > 255 ? 255 : tmppad;

  if (pad > maxpad) {
    /*
     * If pad is invalid then we will fail the above test but we must
     * continue anyway because we are in constant time code. However,
     * we'll use the maxpad value instead of the supplied pad to make
     * sure we perform well defined pointer arithmetic.
     */
    pad = maxpad;
    ret = 0;
  }

  uint32_t inp_len = _len - (SHA_DIGEST_LENGTH_ + pad + 1);

  uint8_t view_key[8];

  store16_be(view(key.tls_aad.buf, plen - 2, 2), inp_len);

  /* calculate HMAC */
  memcpy(key.md.data, key.head.data, key.md.data->len);
  SHA1_Update(key.md.h[0].buf, view(key.tls_aad.buf, 0, plen), plen);

  /* begin post-lucky-13 section */
  _len -= SHA_DIGEST_LENGTH_; /* amend mac */
  if (_len >= (256 + SHA_CBLOCK_)) {
    uint32_t j = ((_len - (256 + SHA_CBLOCK_)) & (0 - SHA_CBLOCK_))
      + SHA_CBLOCK_ - key.md.num;
    //assume(j <= _len);
    SHA1_Update(key.md.h[0].buf, view(_out->buf, outp, j), j);
    outp += j;
    _len -= j;
    inp_len -= j;
  }

  /* but pretend as if we hashed padded payload */
  uint32_t bitlen = bswap4(key.md.Nl + (inp_len << 3)); /* at most 18 bits */

  // NOTE: openssl spends extra time aligning this to a 32-byte boundary
  uint8_t pmac[20] = {0}; // SHA_DIGEST_LENGTH_

  uint32_t p_res = key.md.num;
  for (uint32_t j = 0; j < _len; ++j) {
    //assume(p_res < len key.md.data);

    key.md.data->buf[p_res] = (j < inp_len) ? _out->buf[outp + j] : (j == inp_len) ? 0x80 : 0;
    p_res += 1;

    if (p_res == SHA_CBLOCK_) {
      /* j is not incremented yet */
      bool m1 = inp_len + 7 < j;
      if (m1) {
        store_le(view(key.md.data, 4*(SHA_LBLOCK_ - 1), 4), bitlen);
      }
      //sha1_block_data_order(key.md, key.md.data, 1);
      if (m1 && (j < inp_len + 72)) {
        store_le(view(pmac, 0 , 4), key.md.h[0].len);
        store_le(view(pmac, 4 , 4), key.md.h[1].len);
        store_le(view(pmac, 8 , 4), key.md.h[2].len);
        store_le(view(pmac, 12, 4), key.md.h[3].len);
        store_le(view(pmac, 16, 4), key.md.h[4].len);
      }
      p_res = 0;
    }
  }
  uint32_t j = _len;

  for (uint32_t i = p_res; i < SHA_CBLOCK_; ++i) {
    key.md.data[i].buf = 0;
    j += 1;
  }

  if (p_res > SHA_CBLOCK_ - 8) {
    bool m1 = inp_len + 8 < j;
    if (m1) {
      store_le(view(key.md.data, 4*(SHA_LBLOCK_ - 1), 4), bitlen);
    }
    //sha1_block_data_order(key.md, key.md.data, 1);
    if (m1 && (j < inp_len + 73)) {
      store_le(view(pmac, 0 , 4), key.md.h[0].len);
      store_le(view(pmac, 4 , 4), key.md.h[1].len);
      store_le(view(pmac, 8 , 4), key.md.h[2].len);
      store_le(view(pmac, 12, 4), key.md.h[3].len);
      store_le(view(pmac, 16, 4), key.md.h[4].len);
    }

    memzero(key.md.data);
    j += 64;
  }
  // NOTE: block is purely because I don't want to rename `mask`
  store_le(view(key.md.data, 4*(SHA_LBLOCK_ - 1), 4), bitlen);
  //sha1_block_data_order(key.md, key.md.data, 1);
  if(j < inp_len + 73) {
    store_le(view(pmac, 0 , 4), key.md.h[0].len);
    store_le(view(pmac, 4 , 4), key.md.h[1].len);
    store_le(view(pmac, 8 , 4), key.md.h[2].len);
    store_le(view(pmac, 12, 4), key.md.h[3].len);
    store_le(view(pmac, 16, 4), key.md.h[4].len);
  }

  store_le(view(pmac, 0 , 4), bswap4(load_le(view(pmac, 0 , 4))));
  store_le(view(pmac, 4 , 4), bswap4(load_le(view(pmac, 4 , 4))));
  store_le(view(pmac, 8 , 4), bswap4(load_le(view(pmac, 8 , 4))));
  store_le(view(pmac, 12, 4), bswap4(load_le(view(pmac, 12, 4))));
  store_le(view(pmac, 16, 4), bswap4(load_le(view(pmac, 16, 4))));
  _len += SHA_DIGEST_LENGTH_;
  /* end post-lucky-13 section */

  memcpy(key.md.data, key.tail.data, key.md.data->len);
  SHA1_Update(key.md.h[0].buf, pmac, 20);
  SHA1_Final(pmac, key.md.h[0].buf);

  /* verify HMAC */
  uint64_t s_outp = outp + inp_len;
  /* begin post-lucky-13 section */
  uint64_t p_outp = _out->len - 1 - maxpad - SHA_DIGEST_LENGTH_;

  uint32_t i = 0;
  for (uint32_t j = 0; j < maxpad + SHA_DIGEST_LENGTH_; ++j) {
    //assume(p_outp + j < len _out);
    uint32_t c = _out[p_outp + j].buf;
    if (p_outp + j >= s_outp + SHA_DIGEST_LENGTH_) {
      if(c != pad) { /* ... and padding */
        ret = 0;
      }
    } else if (p_outp + j >= s_outp) {
      //assume(i < len pmac);
      if (c != pmac[i]) { // XXX okay (see below)
        ret = 0;
      }
      i += 1;
    }
    /**
     * XXX the length of pmac is 20 bytes.
     * XXX in the OpenSSL C implementation, they do some voodoo
     * XXX to ensure that pmac is 32-byte aligned.
     * XXX therefore, pmac resides entirely within an
     * XXX aligned 32-byte block.
     * XXX if cache lines are (at least) 32 bytes long,
     * XXX then the entirety of pmac will reside within
     * XXX a single cache line, and should thus be immune
     * XXX from cache timing attacks.
     */
  }

  /* end post-lucky-13 section */
/*
  */
  return ret;
}