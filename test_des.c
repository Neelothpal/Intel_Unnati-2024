#include <stdio.h>
#include <string.h>
#include <mbedtls/des.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int main() {
    int ret;
    mbedtls_des3_context des3;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char key[24]; // 3DES key is 24 bytes (3 * 8 bytes)
    unsigned char iv[8] = {0};
    unsigned char input[32];
    unsigned char encrypted_output[32];
    unsigned char decrypted_output[32];
    const char *pers = "des3_encrypt_decrypt";

    // Initialize the 3DES context and random number generator
    mbedtls_des3_init(&des3);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed the random number generator\n");
        return -1;
    }

    // Generate a random key
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, 24);
    if (ret != 0) {
        printf("Failed to generate a random key\n");
        return -1;
    }

    // Set the encryption key
    ret = mbedtls_des3_set3key_enc(&des3, key);
    if (ret != 0) {
        printf("Failed to set 3DES encryption key\n");
        return -1;
    }

    // Read input message from user
    printf("Enter a 32-byte message to encrypt: ");
    fgets((char *)input, sizeof(input), stdin);
    input[strcspn((char *)input, "\n")] = 0; // Remove newline character

    // Ensure input is exactly 32 bytes by padding with zeros if necessary
    if (strlen((char *)input) < 32) {
        memset(input + strlen((char *)input), 0, 32 - strlen((char *)input));
    }

    // Encrypt the input data in 8-byte blocks
    for (int i = 0; i < 32; i += 8) {
        ret = mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_ENCRYPT, 8, iv, input + i, encrypted_output + i);
        if (ret != 0) {
            printf("Failed to encrypt data\n");
            return -1;
        }
    }

    // Print the encrypted data
    printf("Encrypted data:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", encrypted_output[i]);
    }
    printf("\n");

    // Reset IV for decryption
    memset(iv, 0, 8);

    // Set the decryption key
    ret = mbedtls_des3_set3key_dec(&des3, key);
    if (ret != 0) {
        printf("Failed to set 3DES decryption key\n");
        return -1;
    }

    // Decrypt the encrypted data in 8-byte blocks
    for (int i = 0; i < 32; i += 8) {
        ret = mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_DECRYPT, 8, iv, encrypted_output + i, decrypted_output + i);
        if (ret != 0) {
            printf("Failed to decrypt data\n");
            return -1;
        }
    }

    // Print the decrypted data
    printf("Decrypted data:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", decrypted_output[i]);
    }
    printf("\n");

    // Print the decrypted data as a string
    printf("Decrypted data as a string: %s\n", decrypted_output);

    // Clean up
    mbedtls_des3_free(&des3);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
