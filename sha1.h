#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

void sha1_hash(uint8_t *data, uint64_t length, uint8_t (*result)[20]);

#endif
