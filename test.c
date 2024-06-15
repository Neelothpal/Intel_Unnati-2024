#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>

int main() {
    int ret;
    mbedtls_aes_context aes;
    unsigned char key[32];
    unsigned char iv[16] = {0};
    unsigned char input[16];
    unsigned char encrypted_output[16];
    unsigned char decrypted_output[16];

    // Initialize the AES context
    mbedtls_aes_init(&aes);

    // Set the encryption key
    memset(key, 0x2B, 32);  // Example key, you should use a secure key in real applications
    ret = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (ret != 0) {
        printf("Failed to set AES encryption key\n");
        return -1;
    }

    // Read input message from user
    printf("Enter a 16-byte message to encrypt: ");
    fgets((char *)input, sizeof(input), stdin);
    input[strcspn((char *)input, "\n")] = 0; // Remove newline character

    // Ensure input is exactly 16 bytes by padding with zeros if necessary
    if (strlen((char *)input) < 16) {
        memset(input + strlen((char *)input), 0, 16 - strlen((char *)input));
    }

    // Encrypt the input data
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, encrypted_output);
    if (ret != 0) {
        printf("Failed to encrypt data\n");
        return -1;
    }

    // Print the encrypted data
    printf("Encrypted data:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", encrypted_output[i]);
    }
    printf("\n");

    // Reset IV for decryption
    memset(iv, 0, 16);

    // Set the decryption key
    ret = mbedtls_aes_setkey_dec(&aes, key, 256);
    if (ret != 0) {
        printf("Failed to set AES decryption key\n");
        return -1;
    }

    // Decrypt the encrypted data
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, encrypted_output, decrypted_output);
    if (ret != 0) {
        printf("Failed to decrypt data\n");
        return -1;
    }

    // Print the decrypted data
    printf("Decrypted data:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", decrypted_output[i]);
    }
    printf("\n");

    // Print the decrypted data as a string
    printf("Decrypted data as a string : %s\n", decrypted_output);

    // Clean up
    mbedtls_aes_free(&aes);

    return 0;
}
