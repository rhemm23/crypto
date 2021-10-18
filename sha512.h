#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

void sha512_hash(uint8_t *data, uint64_t length, uint8_t (*result)[64]);

#endif
