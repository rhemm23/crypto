#include "md5.h"

uint32_t T[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static uint32_t left_rotate(uint32_t data, uint8_t n) {
  return (data << n) | (data >> (32 - n));
}

static void round_1_op(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x_k, uint8_t s, uint8_t i) {
  *a += ((b & c) | (~b & d)) + x_k + T[i];
  *a = left_rotate(*a, s);
  *a += b;
}

static void round_2_op(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x_k, uint8_t s, uint8_t i) {
  *a += ((b & d) | (c & ~d)) + x_k + T[i];
  *a = left_rotate(*a, s);
  *a += b;
}

static void round_3_op(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x_k, uint8_t s, uint8_t i) {
  *a += (b ^ c ^ d) + x_k + T[i];
  *a = left_rotate(*a, s);
  *a += b;
}

static void round_4_op(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x_k, uint8_t s, uint8_t i) {
  *a += (c ^ (b | ~d)) + x_k + T[i];
  *a = left_rotate(*a, s);
  *a += b;
}

static void store_le_bytes(uint32_t data, uint8_t *store) {
  store[0] = (uint8_t)data;
  store[1] = (uint8_t)(data >> 8);
  store[2] = (uint8_t)(data >> 16);
  store[3] = (uint8_t)(data >> 24);
}

static uint32_t from_le_bytes(uint8_t *data) {
  return (uint32_t)data[0] |
         (uint32_t)data[1] << 8  |
         (uint32_t)data[2] << 16 |
         (uint32_t)data[3] << 24;
}

void md5_hash(uint8_t *data, uint64_t length, uint8_t (*result)[16]) {
  int pad_bytes = 64 - (length % 64);
  if (pad_bytes < 9) {
    pad_bytes += 64;
  }

  uint64_t total_bytes = length + pad_bytes;
  uint8_t padded_message[total_bytes];

  for (uint64_t i = 0; i < length; i++) {
    padded_message[i] = data[i];
  }

  uint64_t blength = length * 8;
  padded_message[length] = 0x80;

  for (uint64_t i = length + 1; i < total_bytes - 8; i++) {
    padded_message[i] = 0x00;
  }
  for (uint64_t i = total_bytes - 8, j = 0; i < total_bytes; i++, j++) {
    padded_message[i] = (uint8_t)(blength >> (j * 8));
  }

  int blocks = total_bytes / 64;
  uint32_t message[blocks][16];

  for (int i = 0; i < blocks; i++) {
    for (int j = 0; j < 16; j++) {
      message[i][j] = from_le_bytes(&padded_message[(i * 64) + (j * 4)]);
    }
  }

  uint32_t a = 0x67452301;
  uint32_t b = 0xefcdab89;
  uint32_t c = 0x98badcfe;
  uint32_t d = 0x10325476;

  for (int i = 0; i < blocks; i++) {

    uint32_t aa = a;
    uint32_t bb = b;
    uint32_t cc = c;
    uint32_t dd = d;

    // Round 1
    round_1_op(&a, b, c, d, message[i][0], 7, 0);
    round_1_op(&d, a, b, c, message[i][1], 12, 1);    
    round_1_op(&c, d, a, b, message[i][2], 17, 2);
    round_1_op(&b, c, d, a, message[i][3], 22, 3);
    round_1_op(&a, b, c, d, message[i][4], 7, 4);
    round_1_op(&d, a, b, c, message[i][5], 12, 5);    
    round_1_op(&c, d, a, b, message[i][6], 17, 6);
    round_1_op(&b, c, d, a, message[i][7], 22, 7);
    round_1_op(&a, b, c, d, message[i][8], 7, 8);
    round_1_op(&d, a, b, c, message[i][9], 12, 9);    
    round_1_op(&c, d, a, b, message[i][10], 17, 10);
    round_1_op(&b, c, d, a, message[i][11], 22, 11);
    round_1_op(&a, b, c, d, message[i][12], 7, 12);
    round_1_op(&d, a, b, c, message[i][13], 12, 13);    
    round_1_op(&c, d, a, b, message[i][14], 17, 14);
    round_1_op(&b, c, d, a, message[i][15], 22, 15);

    // Round 2
    round_2_op(&a, b, c, d, message[i][1], 5, 16);
    round_2_op(&d, a, b, c, message[i][6], 9, 17);    
    round_2_op(&c, d, a, b, message[i][11], 14, 18);
    round_2_op(&b, c, d, a, message[i][0], 20, 19);
    round_2_op(&a, b, c, d, message[i][5], 5, 20);
    round_2_op(&d, a, b, c, message[i][10], 9, 21);    
    round_2_op(&c, d, a, b, message[i][15], 14, 22);
    round_2_op(&b, c, d, a, message[i][4], 20, 23);
    round_2_op(&a, b, c, d, message[i][9], 5, 24);
    round_2_op(&d, a, b, c, message[i][14], 9, 25);    
    round_2_op(&c, d, a, b, message[i][3], 14, 26);
    round_2_op(&b, c, d, a, message[i][8], 20, 27);
    round_2_op(&a, b, c, d, message[i][13], 5, 28);
    round_2_op(&d, a, b, c, message[i][2], 9, 29);    
    round_2_op(&c, d, a, b, message[i][7], 14, 30);
    round_2_op(&b, c, d, a, message[i][12], 20, 31);

    // Round 3
    round_3_op(&a, b, c, d, message[i][5], 4, 32);
    round_3_op(&d, a, b, c, message[i][8], 11, 33);    
    round_3_op(&c, d, a, b, message[i][11], 16, 34);
    round_3_op(&b, c, d, a, message[i][14], 23, 35);
    round_3_op(&a, b, c, d, message[i][1], 4, 36);
    round_3_op(&d, a, b, c, message[i][4], 11, 37);    
    round_3_op(&c, d, a, b, message[i][7], 16, 38);
    round_3_op(&b, c, d, a, message[i][10], 23, 39);
    round_3_op(&a, b, c, d, message[i][13], 4, 40);
    round_3_op(&d, a, b, c, message[i][0], 11, 41);    
    round_3_op(&c, d, a, b, message[i][3], 16, 42);
    round_3_op(&b, c, d, a, message[i][6], 23, 43);
    round_3_op(&a, b, c, d, message[i][9], 4, 44);
    round_3_op(&d, a, b, c, message[i][12], 11, 45);
    round_3_op(&c, d, a, b, message[i][15], 16, 46);
    round_3_op(&b, c, d, a, message[i][2], 23, 47);

    // Round 4
    round_4_op(&a, b, c, d, message[i][0], 6, 48);
    round_4_op(&d, a, b, c, message[i][7], 10, 49);    
    round_4_op(&c, d, a, b, message[i][14], 15, 50);
    round_4_op(&b, c, d, a, message[i][5], 21, 51);
    round_4_op(&a, b, c, d, message[i][12], 6, 52);
    round_4_op(&d, a, b, c, message[i][3], 10, 53);    
    round_4_op(&c, d, a, b, message[i][10], 15, 54);
    round_4_op(&b, c, d, a, message[i][1], 21, 55);
    round_4_op(&a, b, c, d, message[i][8], 6, 56);
    round_4_op(&d, a, b, c, message[i][15], 10, 57);    
    round_4_op(&c, d, a, b, message[i][6], 15, 58);
    round_4_op(&b, c, d, a, message[i][13], 21, 59);
    round_4_op(&a, b, c, d, message[i][4], 6, 60);
    round_4_op(&d, a, b, c, message[i][11], 10, 61);
    round_4_op(&c, d, a, b, message[i][2], 15, 62);
    round_4_op(&b, c, d, a, message[i][9], 21, 63);

    a += aa;
    b += bb;
    c += cc;
    d += dd;
  }

  // Write result
  store_le_bytes(a, &(*result)[0]);
  store_le_bytes(b, &(*result)[4]);
  store_le_bytes(c, &(*result)[8]);
  store_le_bytes(d, &(*result)[12]);
}
