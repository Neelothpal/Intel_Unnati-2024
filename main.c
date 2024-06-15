#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>

int main() {
    int ret;
    mbedtls_aes_context aes;
    unsigned char key[32];
    unsigned char input[16];
    unsigned char output[16];
    unsigned char iv[16] = {0};

    // Initialize the AES context
    mbedtls_aes_init(&aes);

    // Set the encryption key
    memset(key, 0x2B, 32);  // Example key, you should use a secure key in real applications
    ret = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (ret != 0) {
        printf("Failed to set AES key\n");
        return -1;
    }

    // Encrypt the input data
    memset(input, 0x6B, 16);  // Example input data
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output);
    if (ret != 0) {
        printf("Failed to encrypt data\n");
        return -1;
    }

    // Print the encrypted data
    printf("Encrypted data:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", output[i]);
    }
    printf("\n");

    // Clean up
    mbedtls_aes_free(&aes);
    return 0;
}

