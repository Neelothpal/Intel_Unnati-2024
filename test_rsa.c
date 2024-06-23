#include <stdio.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>

int main() {
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
        return -1;
    }

    // Generate RSA key pair
    ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (ret != 0) {
        printf("Failed to generate RSA key pair\n");
        return -1;
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
        return -1;
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
        return -1;
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

    return 0;
}
