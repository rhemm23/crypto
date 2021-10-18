#ifndef DES_H
#define DES_H

#include <stdint.h>

#define U32_MASK 0x00000001
#define U64_MASK 0x0000000000000001

uint64_t des_encrypt(uint64_t data, uint64_t key);

uint64_t des_decrypt(uint64_t data, uint64_t key);

#endif
