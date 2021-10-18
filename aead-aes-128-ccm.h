#ifndef AEAD_AES_128_CCM_H
#define AEAD_AES_128_CCM_H

#include "aes-128-ccm.h"

uint8_t * aead_aes_128_ccm_encrypt(uint8_t key[16], uint8_t n[12], uint8_t *p, uint8_t *a, uint64_t plen, uint64_t alen);

#endif
