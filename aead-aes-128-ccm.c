#include "aead-aes-128-ccm.h"

uint8_t * aead_aes_128_ccm_encrypt(uint8_t key[16], uint8_t n[12], uint8_t *p, uint8_t *a, uint64_t plen, uint64_t alen) {
  return aes_128_ccm_encrypt(key, p, a, &n[0], plen, alen, 12, 16);
}
