#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#define X2S_KEY_SIZE 32
#define X2S_NONCE_SIZE 12
#define X2S_GCM_TAG_SIZE 16

int encryption_init(const unsigned char key[X2S_KEY_SIZE]);
int encryption_is_active(void);

int encrypt(const unsigned char* plaintext, size_t plaintext_len,
            unsigned char** output, size_t* output_len);

int decrypt(const unsigned char* input, size_t input_len,
            unsigned char** plaintext, size_t* plaintext_len);

#endif
