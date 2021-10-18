#ifndef MD5_H
#define MD5_H

#include <stdint.h>

void md5_hash(uint8_t *data, uint64_t length, uint8_t (*result)[16]);

#endif
