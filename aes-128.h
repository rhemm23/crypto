#ifndef AES_128_H
#define AES_128_H

#include <stdint.h>

void aes_128_encrypt(uint8_t data[16], uint8_t key[16], uint8_t (*result)[16]);

void aes_128_decrypt(uint8_t data[16], uint8_t key[16], uint8_t (*result)[16]);

#endif
