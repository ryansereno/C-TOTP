#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TOTP_DURATION 30
#define TOTP_LENGTH 6
#define MAX_KEY_LENGTH 256

static const int base32_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1};

void to_uppercase(char *str) {
  for (int i = 0; str[i]; i++) {
    str[i] = toupper(str[i]);
  }
}

void remove_padding(char *str) {
  int len = strlen(str);
  while (len > 0 && str[len - 1] == '=') {
    str[--len] = '\0';
  }
}

int base32_decode(const char *input, uint8_t *output, size_t output_size) {
  size_t input_len = strlen(input);
  size_t output_len = 0;
  uint32_t buffer = 0;
  int bits = 0;

  for (size_t i = 0; i < input_len; i++) {
    int val = base32_decode_table[(unsigned char)input[i]];
    if (val == -1) {
      return -1;
    }

    buffer = (buffer << 5) | val;
    bits += 5;

    if (bits >= 8) {
      if (output_len >= output_size) {
        return -1;
      }
      output[output_len++] = (buffer >> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }

  return output_len;
}

uint64_t current_unix_time() { return (uint64_t)time(NULL); }

uint64_t get_count() { return current_unix_time() / TOTP_DURATION; }

void counter_to_bits(uint64_t counter, uint8_t *bytes) {
  for (int i = 7; i >= 0; i--) {
    bytes[i] = counter & 0xFF;
    counter >>= 8;
  }
}

uint32_t dynamic_truncation(const uint8_t *bytes) {
  int offset = bytes[19] & 0x0F;
  return ((bytes[offset] & 0x7F) << 24) | ((bytes[offset + 1] & 0xFF) << 16) |
         ((bytes[offset + 2] & 0xFF) << 8) | (bytes[offset + 3] & 0xFF);
}

uint32_t generate_hotp(const uint8_t *key, size_t key_len, uint64_t counter) {
  uint8_t message[8];
  uint8_t hmac_result[EVP_MAX_MD_SIZE];
  unsigned int hmac_len;

  counter_to_bits(counter, message);

  HMAC(EVP_sha1(), key, key_len, message, 8, hmac_result, &hmac_len);

  uint32_t truncated = dynamic_truncation(hmac_result);
  uint32_t modulo = 1;
  for (int i = 0; i < TOTP_LENGTH; i++) {
    modulo *= 10;
  }

  return truncated % modulo;
}

int main() {
  char key_input[MAX_KEY_LENGTH];
  uint8_t decoded_key[MAX_KEY_LENGTH];
  int decoded_len;

  printf("Enter secret key: ");
  if (!fgets(key_input, sizeof(key_input), stdin)) {
    fprintf(stderr, "Error reading input\n");
    return 1;
  }

  key_input[strcspn(key_input, "\n")] = '\0';

  to_uppercase(key_input);
  remove_padding(key_input);

  decoded_len = base32_decode(key_input, decoded_key, sizeof(decoded_key));
  if (decoded_len < 0) {
    fprintf(stderr, "Invalid base32 key\n");
    return 1;
  }

  printf("TOTP Generator - Press Ctrl+C to exit\n\n");

  while (1) {
    uint32_t totp = generate_hotp(decoded_key, decoded_len, get_count());
    printf("\rYour passcode: %06u", totp);
    fflush(stdout);
    sleep(1);
  }

  return 0;
}
