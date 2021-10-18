#include "sha1.h"

static uint32_t left_rotate(uint32_t data, uint8_t n) {
  return (data << n) | (data >> (32 - n));
}

static uint32_t func(uint8_t t, uint32_t b, uint32_t c, uint32_t d) {
  if (t < 20) {
    return (b & c) | (~b & d);
  } else if (t < 40) {
    return (b ^ c ^ d);
  } else if (t < 60) {
    return (b & c) | (b & d) | (c & d);
  } else {
    return (b ^ c ^ d);
  }
}

void sha1_hash(uint8_t *data, uint64_t length, uint8_t (*result)[20]) {

  uint32_t pad_bytes = 64 - (length % 64);

  if (pad_bytes < 9) {
    pad_bytes += 64;
  }

  uint32_t total_length = length + pad_bytes;
  uint8_t padded_message[total_length];

  // Copy data
  for (uint64_t i = 0; i < length; i++) {
    padded_message[i] = data[i];
  }

  // Required '1'
  padded_message[length] = 0x80;

  // Add zeros
  for (uint64_t i = length + 1; i < total_length - 8; i++) {
    padded_message[i] = 0x00;
  }

  // Store length bytes
  uint64_t blen = length * 8;
  for (uint64_t i = total_length - 8, j = 0; i < total_length; i++, j++) {
    padded_message[i] = (uint8_t)(blen >> (56 - (j * 8)));
  }

  uint32_t blocks = (length + pad_bytes) / 64;
  uint32_t message[blocks][16];

  // Turn bytes into words
  for (int i = 0; i < blocks; i++) {
    for (int j = 0; j < 16; j++) {
      uint32_t word = 0;
      for (int k = 0; k < 4; k++) {
        word |= ((uint32_t)padded_message[(i * 64) + (j * 4) + k]) << (24 - (k * 8));
      }
      message[i][j] = word;
    }
  }

  // Initialize all variables
  uint32_t H0 = 0x67452301;
  uint32_t H1 = 0xEFCDAB89;
  uint32_t H2 = 0x98BADCFE;
  uint32_t H3 = 0x10325476;
  uint32_t H4 = 0xC3D2E1F0;

  uint32_t W[80];
  uint32_t K[80];

  // Setup constant values
  for (uint8_t t = 0; t < 20; t++) {
    K[t] = 0x5A827999;
  }
  for (uint8_t t = 20; t < 40; t++) {
    K[t] = 0x6ED9EBA1;
  }
  for (uint8_t t = 40; t < 60; t++) {
    K[t] = 0x8F1BBCDC;
  }
  for (uint8_t t = 60; t < 80; t++) {
    K[t] = 0xCA62C1D6;
  }

  // Iterate over blocks
  for (int i = 0; i < blocks; i++) {
    for (uint8_t t = 0; t < 16; t++) {
      W[t] = message[i][t];
    }
    for (uint8_t t = 16; t < 80; t++) {
      W[t] = left_rotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    uint32_t A = H0;
    uint32_t B = H1;
    uint32_t C = H2;
    uint32_t D = H3;
    uint32_t E = H4;

    for (uint8_t t = 0; t < 80; t++) {
      uint32_t TEMP = left_rotate(A, 5) + func(t, B, C, D) + E + W[t] + K[t];

      E = D;
      D = C;
      C = left_rotate(B, 30);
      B = A;
      A = TEMP;
    }
    H0 += A;
    H1 += B;
    H2 += C;
    H3 += D;
    H4 += E;
  }

  // Write result
  uint32_t words[] = { H0, H1, H2, H3, H4 };
  for (int i = 0; i < 20; i++) {
    (*result)[i] = (uint8_t)(words[i / 4] >> (24 - ((i % 4) * 8)));
  }
}
