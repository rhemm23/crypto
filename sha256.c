#include "sha256.h"

uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotate_right(uint32_t data, uint8_t n) {
  return (data >> n) | (data << (32 - n));
}

static uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ ((~x) & z);
}

static uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t BSIG0(uint32_t x) {
  return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

static uint32_t BSIG1(uint32_t x) {
  return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

static uint32_t SSIG0(uint32_t x) {
  return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

static uint32_t SSIG1(uint32_t x) {
  return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}

void sha256_hash(uint8_t *data, uint64_t length, uint8_t (*result)[32]) {
  uint8_t pad_bytes = 64 - (length % 64);
  if (pad_bytes < 9) {
    pad_bytes += 64;
  }

  uint64_t total_length = length + pad_bytes;
  uint8_t padded_message[total_length];

  for (uint64_t i = 0; i < length; i++) {
    padded_message[i] = data[i];
  }

  uint64_t blength = length * 8;
  padded_message[length] = 0x80;

  for (uint64_t i = length + 1; i < total_length - 8; i++) {
    padded_message[i] = 0x00;
  }
  for (uint64_t i = total_length - 8, j = 0; i < total_length; i++, j++) {
    padded_message[i] = (uint8_t)(blength >> (56 - (j * 8)));
  }

  uint8_t blocks = total_length / 64;
  uint32_t message[blocks][16];

  for (int i = 0; i < blocks; i++) {
    for (int j = 0; j < 16; j++) {
      uint32_t word = 0;
      for (int k = 0; k < 4; k++) {
        word |= ((uint32_t)padded_message[(i * 64) + (j * 4) + k]) << (24 - (k * 8));
      }
      message[i][j] = word;
    }
  }

  // Variable init
  uint32_t H0 = 0x6a09e667;
  uint32_t H1 = 0xbb67ae85;
  uint32_t H2 = 0x3c6ef372;
  uint32_t H3 = 0xa54ff53a;
  uint32_t H4 = 0x510e527f;
  uint32_t H5 = 0x9b05688c;
  uint32_t H6 = 0x1f83d9ab;
  uint32_t H7 = 0x5be0cd19;

  uint32_t W[64];

  for (int i = 0; i < blocks; i++) {
    for (int t = 0; t < 16; t++) {
      W[t] = message[i][t];
    }
    for (int t = 16; t < 64; t++) {
      W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
    }

    uint32_t A = H0;
    uint32_t B = H1;
    uint32_t C = H2;
    uint32_t D = H3;
    uint32_t E = H4;
    uint32_t F = H5;
    uint32_t G = H6;
    uint32_t H = H7;

    for (int t = 0; t < 64; t++) {
      uint32_t TEMP1 = H + BSIG1(E) + CH(E, F, G) + K[t] + W[t];
      uint32_t TEMP2 = BSIG0(A) + MAJ(A, B, C);
      
      H = G;
      G = F;
      F = E;
      E = D + TEMP1;
      D = C;
      C = B;
      B = A;
      A = TEMP1 + TEMP2;
    }

    H0 += A;
    H1 += B;
    H2 += C;
    H3 += D;
    H4 += E;
    H5 += F;
    H6 += G;
    H7 += H;
  }

  // Write result
  uint32_t words[8] = { H0, H1, H2, H3, H4, H5, H6, H7 };
  for (int i = 0; i < 32; i++) {
    (*result)[i] = (uint8_t)(words[i / 4] >> (24 - ((i % 4) * 8)));
  }
}