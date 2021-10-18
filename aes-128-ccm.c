#include "aes-128-ccm.h"

uint8_t * aes_128_ccm_encrypt(uint8_t key[16], uint8_t *p, uint8_t *a, uint8_t *n, uint64_t plen, uint64_t alen, uint64_t nlen, uint8_t t) {

  uint8_t alen_size = 10;
  if (alen == 0) {
    alen_size = 0;
  } else if (alen < 65280) {
    alen_size = 2;
  } else if (alen < 4294967296) {
    alen_size = 6;
  }

  int u = (alen + alen_size + 15) / 16;
  int r = (plen + 15) / 16;
  int q = (15 - nlen);

  int blen = u + r + 1;

  uint8_t b[blen][16];

  uint8_t tlen_flag = (t - 2) >> 1;
  uint8_t qlen_flag = (uint8_t)(q - 1);
  uint8_t adat_flag = (uint8_t)(alen > 0);

  b[0][0] = (adat_flag << 6) | (tlen_flag << 3) | qlen_flag;

  // Copy nonce
  for (int i = 0; i < nlen; i++) {
    b[0][i + 1] = n[i];
  }

  // Copy plen bytes
  for (int i = 0; i < q; i++) {
    b[0][i + nlen + 1] = (uint8_t)(plen >> ((q - i - 1) * 8));
  }

  // Copy associated data
  if (alen > 0) {
    if (alen_size == 2) {
      uint8_t alen_h = (uint8_t)(alen >> 8);
      uint8_t alen_l = (uint8_t)(alen & 0xff);

      b[1][0] = alen_h;
      b[1][1] = alen_l;
    } else if (alen_size == 6) {
      b[1][0] = 0xff;
      b[1][1] = 0xfe;

      for (int i = 0; i < 4; i++) {
        b[1][i + 2] = (uint8_t)(alen >> ((3 - i) * 8));
      }
    } else {
      b[1][0] = 0xff;
      b[1][1] = 0xff;

      for (int i = 0; i < 8; i++) {
        b[1][i + 2] = (uint8_t)(alen >> ((7 - i) * 8));
      }
    }

    // Copy associated data
    for (int i = 0; i < alen; i++) {
      int b_ind = (alen_size + i) / 16;
      int o_ind = (alen_size + i) % 16;

      b[b_ind + 1][o_ind] = a[i];
    }

    // Associated data padding
    int last_b_ind = (alen_size + alen - 1) / 16;
    int last_o_ind = (alen_size + alen - 1) % 16;

    for (int i = last_o_ind + 1; i < 16; i++) {
      b[last_b_ind + 1][i] = 0x00;
    }
  }

  // Format payload
  for (uint64_t i = 0; i < plen; i++) {
    int p_ind = i / 16;
    int o_ind = i % 16;

    b[p_ind + u + 1][o_ind] = p[i];
  }

  uint8_t y[blen][16];
  aes_128_encrypt(b[0], key, &y[0]);
  
  for (int i = 1; i < blen; i++) {
    uint8_t form[16];
    for (int j = 0; j < 16; j++) {
      form[j] = b[i][j] ^ y[i - 1][j];
    }
    aes_128_encrypt(form, key, &y[i]);
  }

  // Build counter blocks
  uint8_t ctr[r + 1][16];
  for (uint64_t i = 0; i < r + 1; i++) {
    ctr[i][0] = qlen_flag;
    for (int j = 0; j < nlen; j++) {
      ctr[i][j + 1] = n[j];
    }
    for (int j = 0; j < q; j++) {
      ctr[i][j + nlen + 1] = (uint8_t)(i >> ((q - j - 1) * 8));
    }
  }

  uint8_t s[r + 1][16];
  for (int i = 0; i < r + 1; i++) {
    aes_128_encrypt(ctr[i], key, &s[i]);
  }

  // Allocate mem for result
  uint8_t *c = (uint8_t*)malloc(sizeof(uint8_t) * (plen + t));

  // Resulting payload
  for (uint64_t i = 0; i < plen; i++) {
    int s_ind = i / 16;
    int o_ind = i % 16;

    c[i] = p[i] ^ s[s_ind + 1][o_ind];
  }

  // Calculate tag
  for (int i = 0; i < t; i++) {
    c[plen + i] = y[blen - 1][i] ^ s[0][i];
  }
  return c;
}
