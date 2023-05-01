// Headers:
#include "stdlib.h"
#include "stdio.h"
#include "stdbool.h"
#include "string.h"
#include "ctype.h"
#include "stdint.h"
#include "limits.h"

// Functions:

static uint64_t permut(uint64_t src, int srcn, int dstn, const int *numbers);

static uint32_t f_func(uint32_t src, uint64_t key48);

static void des_keys(uint64_t key, uint64_t *keys);

static uint64_t encode_block(uint64_t block, const uint64_t *keys);

static uint64_t decode_block(uint64_t block, const uint64_t *keys);

static void des_file(FILE *input, uint64_t key, bool decode, FILE *output);

static uint64_t get_block(FILE *input, int *readen);

static void put_block(uint64_t block, FILE *output);

// Global data:

const int PRIMARY_PERMUT[64] = {
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

const int E_FUNC_PERMUT[48] = {
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// T = 8 * Si
// Si = 4 * ai
// ai = 16 * bi
const uint32_t S_TABLE[8][4][16] = {
  /* b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15  */
  /* S1 */ {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, // a0
    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, // a1
    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, // a2
    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }, // a3
  },
  /* S2 */ {
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, // a0
    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, // a1
    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, // a2
    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }, // a3
  },
  /* S3 */ {
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, // a0
    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, // a1
    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, // a2
    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }, // a3
  },
  /* S4 */ {
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, // a0
    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, // a1
    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, // a2
    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }, // a3
  },
  /* S5 */ {
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, // a0
    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, // a1
    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, // a2
    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }, // a3
  },
  /* S6 */ {
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, // a0
    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, // a1
    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, // a2
    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }, // a3
  },
  /* S7 */ {
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, // a0
    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, // a1
    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, // a2
    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }, // a3
  },
  /* S8 */ {
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, // a0
    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, // a1
    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, // a2
    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }, // a3
  }
};

const int P_PERMUT[32] = {
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

const int CD_PERMUT[56] = {
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

const int SHIFT_NUM[16] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

const int KI_PERMUT[48] = {
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const int FINALY_PERMUT[64] = {
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

// Implementation:

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Encode/decode files with Data Encryption Standard\n");
    printf("usage:\ndesus (encode/decode) <key> <input-file> <output-file>\n");
    printf("  encode        encoding mode\n");
    printf("  decode        decoding mode\n");
    printf("  <key>         8 ascii characters as a key to encode/decode data\n");
    printf("  <input-file>  name of a file to encode/decode\n");
    printf("  <output-file> name of a file where to store the result\n");
    return EXIT_SUCCESS;
  }
  if (argc < 5) {
    fprintf(stderr, "desus: error: not enough arguments\n");
    return EXIT_FAILURE;
  }
  // mode
  bool decode = false;
  if (strcmp(argv[1], "encode") == 0) {
    decode = false;
  }
  else if (strcmp(argv[1], "decode") == 0) {
    decode = true;
  }
  else {
    fprintf(stderr, "desus: error: unkown mode \'%s\'\n", argv[1]);
    return EXIT_FAILURE;
  }
  // key
  uint64_t key = 0;
  const char *ascii = argv[2];
  while (*ascii != '\0') {
    key <<= CHAR_BIT;
    key |= *ascii;
    ascii++;
  }
  key <<= 1;
  // files
  FILE *input = fopen(argv[3], "rb");
  FILE *output = fopen(argv[4], "wb");
  if (input == NULL) {
    if (output != NULL) fclose(output);
    fprintf(stderr, "desus: error: fail to open a file \'%s\'\n", argv[3]);
    return EXIT_FAILURE;
  }
  if (output == NULL) {
    fclose(input);
    fprintf(stderr, "desus: error: fail to open a file \'%s\'\n", argv[4]);
    return EXIT_FAILURE;
  }
  // des
  des_file(input, key, decode, output);
  //
  return EXIT_SUCCESS;
}

uint64_t permut(uint64_t src, int srcn, int dstn, const int *numbers) {
  uint64_t dst = 0;
  for (int i = 0; i < dstn; i++) {
    uint64_t t = (src >> (srcn - numbers[i])) & 1;
    dst <<= 1;
    dst |= (t != 0) ? 1 : 0;
  }
  return dst;
}

void des_file(FILE *input, uint64_t key, bool decode, FILE *output) {
  uint64_t keys[16] = {0};
  des_keys(key, keys);
  uint64_t(*des_block)(uint64_t block, const uint64_t *keys);
  des_block = (decode) ? decode_block : encode_block;
  for (;;) {
    int readen = 0;
    uint64_t block = get_block(input, &readen);
    if (readen == 0) break;
    block = des_block(block, keys);
    put_block(block, output);
  }
}

uint64_t get_block(FILE *input, int *readen) {
  *readen = 0;
  uint64_t block = 0;
  for (int i = 0; i < sizeof(block); i++) {
    block <<= CHAR_BIT;
    int val = fgetc(input);
    if (val == EOF) {
      continue;
    }
    ++*readen;
    block |= val;
  }
  return block;
}

void put_block(uint64_t block, FILE *output) {
  const int char_mask = (1 << CHAR_BIT) - 1;
  for (int i = 0; i < sizeof(block); i++) {
    int shift = (sizeof(block) - 1 - i) * CHAR_BIT;
    int val = (block >> shift) & char_mask;
    fputc(val, output);
  }
}

void des_keys(uint64_t key, uint64_t *keys) {
  uint64_t cdi = permut(key, 64, 56, CD_PERMUT);
  uint64_t ci = (cdi >> 28) & 0xFFFFFFF;
  uint64_t di = cdi & 0xFFFFFFF;
  for (int i = 0; i < 16; i++) {
    int shift = SHIFT_NUM[i];
    ci = ((ci << shift) | (ci >> (28 - shift))) & 0xFFFFFFF;
    di = ((di << shift) | (di >> (28 - shift))) & 0xFFFFFFF;
    cdi = (ci << 28) | di;
    keys[i] = permut(cdi, 56, 48, KI_PERMUT);
  }
}

uint64_t encode_block(uint64_t block, const uint64_t *keys) {
  // primary
  block = permut(block, 64, 64, PRIMARY_PERMUT);
  uint64_t left = (block >> 32) & 0xFFFFFFFF;
  uint64_t right = block & 0xFFFFFFFF;
  // loop
  for (int i = 0; i < 16; i++) {
    uint32_t x = f_func(left, keys[i]);
    uint32_t y = x ^ right;
    right = left;
    left = y;
  }
  // final
  block = (left << 32) | right;
  return permut(block, 64, 64, FINALY_PERMUT);
}

uint64_t decode_block(uint64_t block, const uint64_t *keys) {
  // primary
  block = permut(block, 64, 64, PRIMARY_PERMUT);
  uint64_t left = (block >> 32) & 0xFFFFFFFF;
  uint64_t right = block & 0xFFFFFFFF;
  // loop
  for (int i = 0; i < 16; i++) {
    uint32_t y = left;
    left = right;
    uint32_t x = f_func(left, keys[15 - i]);
    right = y ^ x;
  }
  // final
  block = (left << 32) | right;
  return permut(block, 64, 64, FINALY_PERMUT);
}

uint32_t f_func(uint32_t src, uint64_t key48) {
  uint64_t x = permut(src, 32, 48, E_FUNC_PERMUT) ^ key48;
  uint32_t s = 0;
  for (int si = 0; si < 8; si++) {
    uint64_t b6 = (x >> (48 - 6 - si * 6)) & 0b111111;
    uint64_t a = ((b6 >> 4) & 2) + (b6 & 1);
    uint64_t b = (b6 >> 1) & 0b1111;
    uint32_t b4 = S_TABLE[si][a][b] & 0xF;
    s <<= 4;
    s |= b4;
  }
  return permut(s, 32, 32, P_PERMUT);
}

//
