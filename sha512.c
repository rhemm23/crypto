#include "sha512.h"

uint64_t K[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

static uint64_t rotate_right(uint64_t data, uint8_t n) {
  return (data >> n) | (data << (64 - n));
}

static uint64_t CH(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ ((~x) & z);
}

static uint64_t MAJ(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t BSIG0(uint64_t x) {
  return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

static uint64_t BSIG1(uint64_t x) {
  return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

static uint64_t SSIG0(uint64_t x) {
  return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
}

static uint64_t SSIG1(uint64_t x) {
  return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

void sha512_hash(uint8_t *data, uint64_t length, uint8_t (*result)[64]) {
  int pad_bytes = 128 - (length % 128);
  if (pad_bytes < 17) {
    pad_bytes += 128;
  }

  uint64_t total_bytes = length + pad_bytes;
  uint8_t padded_message[total_bytes];

  for (uint64_t i = 0; i < length; i++) {
    padded_message[i] = data[i];
  }

  padded_message[length] = 0x80;

  for (uint64_t i = length + 1; i < total_bytes - 8; i++) {
    padded_message[i] = 0x00;
  }

  uint64_t blength = length * 8;
  for (uint64_t i = total_bytes - 8, j = 0; i < total_bytes; i++, j++) {
    padded_message[i] = (uint8_t)(blength >> (56 - (j * 8)));
  }

  uint8_t blocks = total_bytes / 128;
  uint64_t message[blocks][16];

  for (int i = 0; i < blocks; i++) {
    for (int j = 0; j < 16; j++) {
      uint64_t word = 0;
      for (int k = 0; k < 8; k++) {
        word |= ((uint64_t)padded_message[(i * 128) + (j * 8) + k]) << (56 - (k * 8));
      }
      message[i][j] = word;
    }
  }

  // Initialize variables
  uint64_t H0 = 0x6a09e667f3bcc908;
  uint64_t H1 = 0xbb67ae8584caa73b;
  uint64_t H2 = 0x3c6ef372fe94f82b;
  uint64_t H3 = 0xa54ff53a5f1d36f1;
  uint64_t H4 = 0x510e527fade682d1;
  uint64_t H5 = 0x9b05688c2b3e6c1f;
  uint64_t H6 = 0x1f83d9abfb41bd6b;
  uint64_t H7 = 0x5be0cd19137e2179;

  uint64_t W[80];

  for (int i = 0; i < blocks; i++) {
    for (int t = 0; t < 16; t++) {
      W[t] = message[i][t];
    }
    for (int t = 16; t < 80; t++) {
      W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
    }

    uint64_t A = H0;
    uint64_t B = H1;
    uint64_t C = H2;
    uint64_t D = H3;
    uint64_t E = H4;
    uint64_t F = H5;
    uint64_t G = H6;
    uint64_t H = H7;

    for (int t = 0; t < 80; t++) {
      uint64_t TEMP1 = H + BSIG1(E) + CH(E, F, G) + K[t] + W[t];
      uint64_t TEMP2 = BSIG0(A) + MAJ(A, B, C);
      
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
  uint64_t words[8] = { H0, H1, H2, H3, H4, H5, H6, H7 };
  for (int i = 0; i < 64; i++) {
    (*result)[i] = (uint8_t)(words[i / 8] >> (56 - ((i % 8) * 8)));
  }
}