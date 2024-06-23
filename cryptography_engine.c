#include <stdio.h>
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/des.h>
#include <mbedtls/aes.h>

void sha256_hash() {
    int ret;
    mbedtls_sha256_context sha256;
    unsigned char input[32];
    unsigned char output[32]; // SHA-256 produces a 32-byte (256-bit) hash

    // Initialize the SHA-256 context
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts_ret(&sha256, 0); // 0 for SHA-256 (not SHA-224)

    // Read input message from user
    printf("Enter a message to hash (max 32 bytes): ");
    fgets((char *)input, sizeof(input), stdin);
    input[strcspn((char *)input, "\n")] = 0; // Remove newline character

    // Ensure input is exactly 32 bytes by padding with zeros if necessary
    if (strlen((char *)input) < 32) {
        memset(input + strlen((char *)input), 0, 32 - strlen((char *)input));
    }

    // Hash the input data
    mbedtls_sha256_update_ret(&sha256, input, 32);
    mbedtls_sha256_finish_ret(&sha256, output);

    // Print the hash
    printf("SHA-256 hash:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", output[i]);
    }
    printf("\n");

    // Clean up
    mbedtls_sha256_free(&sha256);
}

void rsa_encrypt_decrypt() {
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[256];
    unsigned char encrypted_output[256];
    unsigned char decrypted_output[256];
    const char *pers = "rsa_encrypt_decrypt";

    // Initialize contexts
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed the random number generator\n");
        return;
    }

    // Generate RSA key pair
    ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (ret != 0) {
        printf("Failed to generate RSA key pair\n");
        return;
    }

    // Read input message from user
    printf("Enter a message to encrypt (max 245 bytes): ");
    fgets((char *)input, sizeof(input) - 1, stdin);
    input[strcspn((char *)input, "\n")] = 0; // Remove newline character

    // Encrypt the input data using the public key
    size_t input_len = strlen((char *)input);
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, input_len, input, encrypted_output);
    if (ret != 0) {
        printf("Failed to encrypt data\n");
        return;
    }

    // Print the encrypted data
    printf("Encrypted data:\n");
    for (size_t i = 0; i < rsa.len; i++) {
        printf("%02X ", encrypted_output[i]);
    }
    printf("\n");

    // Decrypt the encrypted data using the private key
    size_t decrypted_len;
    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &decrypted_len, encrypted_output, decrypted_output, sizeof(decrypted_output));
    if (ret != 0) {
        printf("Failed to decrypt data\n");
        return;
    }

    // Print the decrypted data
    printf("Decrypted data:\n");
    for (size_t i = 0; i < decrypted_len; i++) {
        printf("%02X ", decrypted_output[i]);
    }
    printf("\n");

    // Print the decrypted data as a string
    decrypted_output[decrypted_len] = '\0'; // Null-terminate the decrypted string
    printf("Decrypted data as a string: %s\n", decrypted_output);

    // Clean up
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void des3_encrypt_decrypt() {
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
        return;
    }

    // Generate a random key
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, 24);
    if (ret != 0) {
        printf("Failed to generate a random key\n");
        return;
    }

    // Set the encryption key
    ret = mbedtls_des3_set3key_enc(&des3, key);
    if (ret != 0) {
        printf("Failed to set 3DES encryption key\n");
        return;
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
            return;
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
        return;
    }

    // Decrypt the encrypted data in 8-byte blocks
    for (int i = 0; i < 32; i += 8) {
        ret = mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_DECRYPT, 8, iv, encrypted_output + i, decrypted_output + i);
        if (ret != 0) {
            printf("Failed to decrypt data\n");
            return;
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
}

void aes_encrypt_decrypt() {
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
        return;
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
        return;
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
        return;
    }

    // Decrypt the encrypted data
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, encrypted_output, decrypted_output);
    if (ret != 0) {
        printf("Failed to decrypt data\n");
        return;
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
}

int main() {
    int choice;

    printf("Select an algorithm:\n");
    printf("1. SHA-256\n");
    printf("2. RSA Encrypt/Decrypt\n");
    printf("3. 3DES Encrypt/Decrypt\n");
    printf("4. AES Encrypt/Decrypt\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    getchar(); // Consume newline character left in input buffer

    switch (choice) {
        case 1:
            sha256_hash();
            break;
        case 2:
            rsa_encrypt_decrypt();
            break;
        case 3:
            des3_encrypt_decrypt();
            break;
        case 4:
            aes_encrypt_decrypt();
            break;
        default:
            printf("Invalid choice\n");
            break;
    }

    return 0;
}
