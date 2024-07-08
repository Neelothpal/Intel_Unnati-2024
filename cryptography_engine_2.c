#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    const char *pers = "rsa_encrypt_decrypt";
    int choice;

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

    printf("Choose operation:\n1. Encrypt\n2. Decrypt\n");
    scanf("%d", &choice);
    getchar(); // Consume newline character left in input buffer

    if (choice == 1) {
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
        ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, input_len, input, encrypted);
        if (ret != 0) {
            printf("Failed to encrypt data\n");
            return;
        }

        // Print the encrypted data
        printf("Encrypted data (in hex):\n");
        for (size_t i = 0; i < rsa.len; i++) {
            printf("%02X ", encrypted[i]);
        }
        printf("\n");

        // Print the RSA public and private keys
        printf("RSA public key:\n");
        mbedtls_pk_write_pubkey_pem(&rsa, encrypted, sizeof(encrypted));
        printf("%s\n", encrypted);
        printf("RSA private key:\n");
        mbedtls_pk_write_key_pem(&rsa, encrypted, sizeof(encrypted));
        printf("%s\n", encrypted);

    } else if (choice == 2) {
        // Read the RSA private key from the user
        printf("Enter the RSA private key: ");
        char private_key[2048];
        fgets(private_key, sizeof(private_key), stdin);
        private_key[strcspn(private_key, "\n")] = 0; // Remove newline character

        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_key(&pk, (unsigned char*)private_key, strlen(private_key) + 1, NULL, 0);
        if (ret != 0) {
            printf("Failed to parse RSA private key\n");
            return;
        }
        mbedtls_rsa_context *rsa_private = mbedtls_pk_rsa(pk);

        // Read encrypted message from user
        printf("Enter encrypted message (in hex, max 512 characters): ");
        char encrypted_hex[512];
        fgets(encrypted_hex, sizeof(encrypted_hex), stdin);
        encrypted_hex[strcspn(encrypted_hex, "\n")] = 0; // Remove newline character

        // Convert hex string to bytes
        size_t encrypted_len = strlen(encrypted_hex) / 2;
        unsigned char encrypted_input[256];
        for (size_t i = 0; i < encrypted_len; i++) {
            sscanf(&encrypted_hex[i * 2], "%2hhx", &encrypted_input[i]);
        }

        // Decrypt the encrypted data using the private key
        size_t decrypted_len;
        ret = mbedtls_rsa_pkcs1_decrypt(rsa_private, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &decrypted_len, encrypted_input, decrypted, sizeof(decrypted));
        if (ret != 0) {
            printf("Failed to decrypt data\n");
            return;
        }

        // Print the decrypted data as a string
        decrypted[decrypted_len] = '\0'; // Null-terminate the decrypted string
        printf("Decrypted data as a string: %s\n", decrypted);

        // Print the decrypted data (in hex)
        printf("Decrypted data (in hex):\n");
        for (size_t i = 0; i < decrypted_len; i++) {
            printf("%02X ", decrypted[i]);
        }
        printf("\n");

        mbedtls_pk_free(&pk);
    }

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
    unsigned char encrypted[32];
    unsigned char decrypted[32];
    const char *pers = "des3_encrypt_decrypt";
    int choice;

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

    printf("Choose operation:\n1. Encrypt\n2. Decrypt\n");
    scanf("%d", &choice);
    getchar(); // Consume newline character left in input buffer

    if (choice == 1) {
        // Generate a random 3DES key
        ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, sizeof(key));
        if (ret != 0) {
            printf("Failed to generate 3DES key\n");
            return;
        }

        // Print the 3DES key
        printf("3DES key (in hex):\n");
        for (int i = 0; i < 24; i++) {
            printf("%02X ", key[i]);
        }
        printf("\n");

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

        // Encrypt the input data
        ret = mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_ENCRYPT, 32, iv, input, encrypted);
        if (ret != 0) {
            printf("Failed to encrypt data\n");
            return;
        }

        // Print the encrypted data
        printf("Encrypted data (in hex):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", encrypted[i]);
        }
        printf("\n");

    } else if (choice == 2) {
        // Read the 3DES key from the user
        printf("Enter the 3DES key (in hex): ");
        char key_hex[48];
        fgets(key_hex, sizeof(key_hex), stdin);
        key_hex[strcspn(key_hex, "\n")] = 0; // Remove newline character

        // Convert hex string to bytes
        for (int i = 0; i < 24; i++) {
            sscanf(&key_hex[i * 2], "%2hhx", &key[i]);
        }

        // Set the decryption key
        ret = mbedtls_des3_set3key_dec(&des3, key);
        if (ret != 0) {
            printf("Failed to set 3DES decryption key\n");
            return;
        }

        // Read encrypted message from user
        printf("Enter encrypted message (in hex, max 64 characters): ");
        char encrypted_hex[64];
        fgets(encrypted_hex, sizeof(encrypted_hex), stdin);
        encrypted_hex[strcspn(encrypted_hex, "\n")] = 0; // Remove newline character

        // Convert hex string to bytes
        size_t encrypted_len = strlen(encrypted_hex) / 2;
        unsigned char encrypted_input[32];
        for (size_t i = 0; i < encrypted_len; i++) {
            sscanf(&encrypted_hex[i * 2], "%2hhx", &encrypted_input[i]);
        }

        // Decrypt the encrypted data
        ret = mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_DECRYPT, 32, iv, encrypted_input, decrypted);
        if (ret != 0) {
            printf("Failed to decrypt data\n");
            return;
        }

        // Print the decrypted data
        printf("Decrypted data (in hex):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", decrypted[i]);
        }
        printf("\n");
    }

    // Clean up
    mbedtls_des3_free(&des3);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void aes_encrypt_decrypt() {
    int ret;
    mbedtls_aes_context aes;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char key[32]; // AES-256 key is 32 bytes
    unsigned char iv[16] = {0};
    unsigned char input[32];
    unsigned char encrypted[32];
    unsigned char decrypted[32];
    const char *pers = "aes_encrypt_decrypt";
    int choice;

    // Initialize the AES context and random number generator
    mbedtls_aes_init(&aes);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed the random number generator\n");
        return;
    }

    printf("Choose operation:\n1. Encrypt\n2. Decrypt\n");
    scanf("%d", &choice);
    getchar(); // Consume newline character left in input buffer

    if (choice == 1) {
        // Generate a random AES key
        ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, sizeof(key));
        if (ret != 0) {
            printf("Failed to generate AES key\n");
            return;
        }

        // Print the AES key
        printf("AES key (in hex):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", key[i]);
        }
        printf("\n");

        // Set the encryption key
        ret = mbedtls_aes_setkey_enc(&aes, key, 256);
        if (ret != 0) {
            printf("Failed to set AES encryption key\n");
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

        // Encrypt the input data
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv, input, encrypted);
        if (ret != 0) {
            printf("Failed to encrypt data\n");
            return;
        }

        // Print the encrypted data
        printf("Encrypted data (in hex):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", encrypted[i]);
        }
        printf("\n");

    } else if (choice == 2) {
        // Read the AES key from the user
        printf("Enter the AES key (in hex): ");
        char key_hex[64];
        fgets(key_hex, sizeof(key_hex), stdin);
        key_hex[strcspn(key_hex, "\n")] = 0; // Remove newline character

        // Convert hex string to bytes
        for (int i = 0; i < 32; i++) {
            sscanf(&key_hex[i * 2], "%2hhx", &key[i]);
        }

        // Set the decryption key
        ret = mbedtls_aes_setkey_dec(&aes, key, 256);
        if (ret != 0) {
            printf("Failed to set AES decryption key\n");
            return;
        }

        // Read encrypted message from user
        printf("Enter encrypted message (in hex, max 64 characters): ");
        char encrypted_hex[64];
        fgets(encrypted_hex, sizeof(encrypted_hex), stdin);
        encrypted_hex[strcspn(encrypted_hex, "\n")] = 0; // Remove newline character

        // Convert hex string to bytes
        size_t encrypted_len = strlen(encrypted_hex) / 2;
        unsigned char encrypted_input[32];
        for (size_t i = 0; i < encrypted_len; i++) {
            sscanf(&encrypted_hex[i * 2], "%2hhx", &encrypted_input[i]);
        }

        // Decrypt the encrypted data
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv, encrypted_input, decrypted);
        if (ret != 0) {
            printf("Failed to decrypt data\n");
            return;
        }

        // Print the decrypted data
        printf("Decrypted data (in hex):\n");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", decrypted[i]);
        }
        printf("\n");
    }

    // Clean up
    mbedtls_aes_free(&aes);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void main() {
    while (1) {
        int choice;
        printf("\nChoose an operation:\n");
        printf("1. SHA-256 Hashing\n");
        printf("2. RSA Encryption/Decryption\n");
        printf("3. 3DES Encryption/Decryption\n");
        printf("4. AES Encryption/Decryption\n");
        printf("5. Exit\n");
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
            case 5:
                exit(0);
            default:
                printf("Invalid choice, please try again.\n");
        }
    }
}
