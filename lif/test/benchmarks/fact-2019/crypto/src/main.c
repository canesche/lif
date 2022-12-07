#include "../include/crypto_secretbox.h"
#include "../../../include/taint.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <stdint.h>

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

    md_state.len = 32;
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

    read(0, md_state.buf, md_state.len * sizeof(uint8_t));
    read(0, header.buf, header.len * sizeof(uint8_t));
    read(0, data.buf, data.len * sizeof(uint8_t));

    // Mark input as secret for ct_grind check:
    ct_secret(md_state.buf, md_state.len);
    ct_secret(mac_out.buf, mac_out.len);
    ct_secret(header.buf, header.len);
    ct_secret(data.buf, data.len);
    ct_secret(&data_plus_mac_size, 1);

    /* 
    _crypto_secretbox(i8* %__v24_c, 
                      i64 %__v310___v24_c_len, 
                      i8* %__v25_m, 
                      i64 %__v311___v25_m_len, 
                      i8* %__v26_n, 
                      i8* %__v27_k)
    */
    //decrypted, ciphertext, nonce, key
    struct timespec start, end;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

    __crypto_secretbox(data.buf, mac_out.buf, header.buf, md_state.buf);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    uint64_t delta = nanoseconds(end) - nanoseconds(start);
    printf("\nTime: %ld\n", delta);

    //write(1, mac_out.buf, mac_out.len * sizeof(uint8_t));
}