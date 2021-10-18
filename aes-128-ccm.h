#ifndef AES_128_CCM_H
#define AES_128_CCM_H

#include "aes-128.h"

#include <stdint.h>
#include <stdlib.h>

uint8_t * aes_128_ccm_encrypt(uint8_t key[16], uint8_t *p, uint8_t *a, uint8_t *n, uint64_t plen, uint64_t alen, uint64_t nlen, uint8_t t);

#endif
