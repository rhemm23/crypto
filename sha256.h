#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

void sha256_hash(uint8_t *data, uint64_t length, uint8_t (*result)[32]);

#endif
