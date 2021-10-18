#include "des.h"

uint8_t s_boxes[8][4][16] = {
  {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
  },
  {
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
  },
  {
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
  },
  {
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
  },
  {
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
  },
  {
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
  },
  {
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
  },
  {
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
  }
};

static uint64_t pc2(uint64_t data) {
  int indices[8][6] = {
    { 13, 16, 10, 23, 0, 4 },
    { 2, 27, 14, 5, 20, 9 },
    { 22, 18, 11, 3, 25, 7 },
    { 15, 6, 26, 19, 12, 1 },
    { 40, 51, 30, 36, 46, 54 },
    { 29, 39, 50, 44, 32, 47 },
    { 43, 48, 38, 55, 33, 52 },
    { 45, 41, 49, 35, 28, 31 }
  };
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 6; j++) {
      result <<= 1;
      result |= ((data >> (63 - indices[i][j])) & U64_MASK);
    }
  }
  return result << 16;
}

static uint32_t final_perm(uint32_t data) {
  int indices[8][4] = {
    { 15, 6, 19, 20 },
    { 28, 11, 27, 16 },
    { 0, 14, 22, 25 },
    { 4, 17, 30, 9 },
    { 1, 7, 23, 13 },
    { 31, 26, 2, 8 },
    { 18, 12, 29, 5 },
    { 21, 10, 3, 24 }
  };
  uint32_t result = 0;
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 4; j++) {
      result <<= 1;
      result |= ((data >> (31 - indices[i][j])) & U32_MASK);
    }
  }
  return result;
}

static uint64_t pc1(uint64_t data) {
  int indices[8][7] = {
    { 56, 48, 40, 32, 24, 16, 8 },
    { 0, 57, 49, 41, 33, 25, 17 },
    { 9, 1, 58, 50, 42, 34, 26 },
    { 18, 10, 2, 59, 51, 43, 35 },
    { 62, 54, 46, 38, 30, 22, 14 },
    { 6, 61, 53, 45, 37, 29, 21 },
    { 13, 5, 60, 52, 44, 36, 28 },
    { 20, 12, 4, 27, 19, 11, 3 }
  };
  uint64_t result = 0;
  for (uint64_t i = 0; i < 8; i++) {
    for (uint64_t j = 0; j < 7; j++) {
      result <<= 1;
      result |= ((data >> (63 - indices[i][j])) & U64_MASK);
    }
  }
  return result << 8;
}

static uint64_t ebit_selection(uint32_t data) {
  int indices[8][6] = {
    { 31, 0, 1, 2, 3, 4 },
    { 3, 4, 5, 6, 7, 8 },
    { 7, 8, 9, 10, 11, 12 },
    { 11, 12, 13, 14, 15, 16 },
    { 15, 16, 17, 18, 19, 20 },
    { 19, 20, 21, 22, 23, 24 },
    { 23, 24, 25, 26, 27, 28 },
    { 27, 28, 29, 30, 31, 0 }
  };
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 6; j++) {
      result <<= 1;
      result |= ((data >> (31 - indices[i][j])) & U32_MASK);
    }
  }
  return result << 16;
}

static uint64_t inverse_initial_permutation(uint64_t data) {
  int indices[8][8] = {
    { 39, 7, 47, 15, 55, 23, 63, 31 },
    { 38, 6, 46, 14, 54, 22, 62, 30 },
    { 37, 5, 45, 13, 53, 21, 61, 29 },
    { 36, 4, 44, 12, 52, 20, 60, 28 },
    { 35, 3, 43, 11, 51, 19, 59, 27 },
    { 34, 2, 42, 10, 50, 18, 58, 26 },
    { 33, 1, 41, 9, 49, 17, 57, 25 },
    { 32, 0, 40, 8, 48, 16, 56, 24 }
  };
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      result <<= 1;
      result |= ((data >> (63 - indices[i][j])) & U64_MASK);
    }
  }
  return result;
}

static uint64_t inital_permutation(uint64_t data) {
  int indices[8][8] = {
    { 57, 49, 41, 33, 25, 17, 9, 1 },
    { 59, 51, 43, 35, 27, 19, 11, 3 },
    { 61, 53, 45, 37, 29, 21, 13, 5 },
    { 63, 55, 47, 39, 31, 23, 15, 7 },
    { 56, 48, 40, 32, 24, 16, 8, 0 },
    { 58, 50, 42, 34, 26, 18, 10, 2 },
    { 60, 52, 44, 36, 28, 20, 12, 4 },
    { 62, 54, 46, 38, 30, 22, 14, 6 }
  };
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      result <<= 1;
      result |= ((data >> (63 - indices[i][j])) & U64_MASK);
    }
  }
  return result;
}

static uint32_t key_left_shift(uint32_t data) {
  return ((data << 1) | ((data & 0x80000000) >> 27));
}

static uint64_t des_crypt(uint64_t data, uint64_t key, uint8_t order) {

  uint32_t l_blocks[17];
  uint32_t r_blocks[17];

  uint32_t c_keys[17];
  uint32_t d_keys[17];

  uint64_t keys[16];

  key = pc1(key);

  c_keys[0] = ((uint32_t)(key >> 36)) << 4;
  d_keys[0] = (uint32_t)(key >> 4);

  for (int i = 1; i < 17; i++) {
    if (i == 1 || i == 2 || i == 9 || i == 16) {
      c_keys[i] = key_left_shift(c_keys[i - 1]);
      d_keys[i] = key_left_shift(d_keys[i - 1]);
    } else {
      uint32_t c_key_temp = key_left_shift(c_keys[i - 1]);
      uint32_t d_key_temp = key_left_shift(d_keys[i - 1]);

      c_keys[i] = key_left_shift(c_key_temp);
      d_keys[i] = key_left_shift(d_key_temp);
    }
  }
  for (int i = 0; i < 16; i++) {
    uint64_t c_key_prt = ((uint64_t)c_keys[i + 1]) << 32;
    uint64_t d_key_prt = ((uint64_t)d_keys[i + 1]) << 4;

    keys[i] = pc2(c_key_prt | d_key_prt);
  }

  data = inital_permutation(data);

  l_blocks[0] = (uint32_t)(data >> 32);
  r_blocks[0] = (uint32_t)data;

  for (int i = 1; i < 17; i++) {
    uint64_t key = (order == 1) ? keys[i - 1] : keys[16 - i];
    uint64_t block = key ^ ebit_selection(r_blocks[i - 1]);
    uint32_t result = 0;

    for (int j = 0; j < 8; j++) {
      uint8_t val = ((uint8_t)((block >> (58 - j * 6)) & 0x3F)) << 2;
      uint8_t row = ((val & 0x80) >> 6) | ((val & 0x04) >> 2);
      uint8_t col = (val >> 3) & 0x0F;

      uint32_t s_box_val = (uint32_t)s_boxes[j][row][col];
      result |= s_box_val << ((7 - j) * 4);
    }

    r_blocks[i] = l_blocks[i - 1] ^ final_perm(result);
    l_blocks[i] = r_blocks[i - 1];
  }

  uint64_t left_exp = (uint64_t)l_blocks[16];
  uint64_t right_exp = ((uint64_t)r_blocks[16]) << 32;

  return inverse_initial_permutation(right_exp | left_exp);
}

uint64_t des_encrypt(uint64_t data, uint64_t key) {
  return des_crypt(data, key, 1);
}

uint64_t des_decrypt(uint64_t data, uint64_t key) {
  return des_crypt(data, key, 0);
}