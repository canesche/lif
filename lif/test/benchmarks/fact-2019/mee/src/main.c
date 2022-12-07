#include "../include/mee.h"
#include "../../../include/taint.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <time.h>
#include <stdint.h>

#include "../include/sha_locl.h"

# define EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_get_key_length

#define AES_MAXNR 14
#define NO_PAYLOAD_LENGTH       ((size_t)-1)
# define data(ctx) ((EVP_AES_HMAC_SHA1 *) EVP_CIPHER_CTX_get_cipher_data(ctx))

#define _NS_PER_SECO_ND 1000000000
#define INLINE __attribute__((__always_inline__)) inline
INLINE uint64_t nanoseconds(struct timespec t) {
    return t.tv_sec * _NS_PER_SECO_ND + t.tv_nsec;
}

int main() {
    uint8ptr_wrapped_ty md_state;
    uint8ptr_wrapped_ty mac_out;
    uint8ptr_wrapped_ty header;
    uint8ptr_wrapped_ty data;

    size_t mac_secret_length = 20;
    size_t sslv3_pad_length = 40;

    md_state.len = sizeof(SHA_CTX);
    mac_out.len = 20;
    header.len = mac_secret_length + sslv3_pad_length
         + 8 /* sequence number */
         + 1 /* record type */
         + 2 /* record length */;
    data.len = 128;

    // All of these buffers are secret, but we mark them as secret inside
    // function __ssl3_cbc_digest_record as a workaround for Lif's
    // taint analysis' overapproximation; otherwise, the entire struct would
    // be considered as tainted, including the length field.
    md_state.buf = (uint8_t *) malloc(md_state.len * sizeof(uint8_t));
    mac_out.buf = (uint8_t *) malloc(mac_out.len * sizeof(uint8_t));
    header.buf = (uint8_t *) malloc(header.len * sizeof(uint8_t));
    data.buf = (uint8_t *) malloc(data.len * sizeof(uint8_t));

    secret uint64_t data_plus_mac_size = data.len - data.buf[127];
    
    SHA1_Init((SHA_CTX *) md_state.buf);
    
    SHA_CTX ctx;
    SHA1_Init(&ctx);

    EVP_AES_HMAC_SHA1 *key = md_state.buf;

    SHA1_Init(&key->head);      
    key->tail = key->head;
    key->md = key->head;
    key->payload_length = NO_PAYLOAD_LENGTH;
    
    size_t plen = key->payload_length;

    read(0, header.buf, header.len * sizeof(uint8_t));
    read(0, data.buf, data.len * sizeof(uint8_t));

    // Mark input as secret for ct_grind check:
    ct_secret(md_state.buf, md_state.len);
    ct_secret(mac_out.buf, mac_out.len);
    ct_secret(header.buf, header.len);
    ct_secret(data.buf, data.len);
    ct_secret(&data_plus_mac_size, 1);

    struct timespec start, end;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

    size_t size = key->aux.tls_aad[plen-4] << 8 | key->aux.tls_aad[plen-3];

    

    _aesni_cbc_hmac_sha1_cipher(data.buf, key, data.buf, data.buf, size);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    uint64_t delta = nanoseconds(end) - nanoseconds(start);
    printf("\nTime: %ld\n", delta);

    //write(1, mac_out.buf, mac_out.len * sizeof(uint8_t));
}