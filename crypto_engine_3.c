#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define RSA_KEY_SIZE 2048
#define EXPONENT 65537
#define BUF_SIZE 512

void handle_mbedtls_error(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    printf("Last error was: -0x%04X - %s\n", -ret, error_buf);
}

void sha256_hash() {
    unsigned char output[32];
    char input[32];

    printf("Enter a message to hash (max 32 bytes): ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (unsigned char *) input, strlen(input));
    mbedtls_md_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    printf("SHA-256 hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
}

void rsa_encrypt_decrypt() {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "rsa_encrypt_decrypt";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        handle_mbedtls_error(ret);
        return;
    }

    printf("Choose an operation:\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("3. Generate RSA Key Pair\n");
    printf("4. Digital Signature\n");
    printf("5. Verify Digital Signature\n");
    printf("Enter your choice: ");
    int choice;
    scanf("%d", &choice);
    getchar(); // consume newline character

    if (choice == 1) {
        // Encrypt
        char input[245];
        printf("Enter a message to encrypt (max 245 bytes): ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;

        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
        mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

        ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_SIZE, EXPONENT);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        unsigned char encrypted[BUF_SIZE];
        size_t olen;
        ret = mbedtls_pk_encrypt(&pk, (unsigned char *) input, strlen(input), encrypted, &olen, sizeof(encrypted), mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        printf("Encrypted data (hex): ");
        for (size_t i = 0; i < olen; i++) {
            printf("%02x", encrypted[i]);
        }
        printf("\n");

        // Save the private key to a PEM file
        unsigned char private_key[16000];
        ret = mbedtls_pk_write_key_pem(&pk, private_key, sizeof(private_key));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        FILE *file = fopen("private_key.pem", "wb");
        if (file == NULL) {
            perror("Error opening file to save private key");
            return;
        }

        fwrite(private_key, 1, strlen((char *)private_key), file);
        fclose(file);

        printf("RSA Private Key saved to private_key.pem\n");

        // Save the public key to a PEM file
        unsigned char public_key[16000];
        ret = mbedtls_pk_write_pubkey_pem(&pk, public_key, sizeof(public_key));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        file = fopen("public_key.pem", "wb");
        if (file == NULL) {
            perror("Error opening file to save public key");
            return;
        }

        fwrite(public_key, 1, strlen((char *)public_key), file);
        fclose(file);

        printf("RSA Public Key saved to public_key.pem\n");

    } else if (choice == 2) {
        // Decrypt
        int use_stored_key = 0;
        char private_key_file[256];
        printf("Do you want to use the private key stored in the folder (private_key.pem) or another key? (1 for stored, 2 for another): ");
        scanf("%d", &use_stored_key);
        getchar(); // consume newline character

        if (use_stored_key == 1) {
            strcpy(private_key_file, "private_key.pem");
        } else if (use_stored_key == 2) {
            printf("Enter the path to the RSA private key file: ");
            fgets(private_key_file, sizeof(private_key_file), stdin);
            private_key_file[strcspn(private_key_file, "\n")] = 0;
        } else {
            printf("Invalid choice.\n");
            return;
        }

        FILE *file = fopen(private_key_file, "rb");
        if (file == NULL) {
            perror("Error opening private key file");
            return;
        }

        fseek(file, 0, SEEK_END);
        long private_key_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *private_key_pem = malloc(private_key_len + 1);
        fread(private_key_pem, 1, private_key_len, file);
        private_key_pem[private_key_len] = '\0';
        fclose(file);

        char encrypted_hex[BUF_SIZE * 2];
        printf("Enter encrypted message (in hex, max 512 characters): ");
        fgets(encrypted_hex, sizeof(encrypted_hex), stdin);
        encrypted_hex[strcspn(encrypted_hex, "\n")] = 0;

        size_t encrypted_len = strlen(encrypted_hex) / 2;
        unsigned char encrypted[encrypted_len];
        for (size_t i = 0; i < encrypted_len; i++) {
            sscanf(&encrypted_hex[i * 2], "%2hhx", &encrypted[i]);
        }

        ret = mbedtls_pk_parse_key(&pk, (unsigned char *) private_key_pem, strlen(private_key_pem) + 1, NULL, 0);
        free(private_key_pem);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        unsigned char decrypted[BUF_SIZE];
        size_t olen;
        ret = mbedtls_pk_decrypt(&pk, encrypted, encrypted_len, decrypted, &olen, sizeof(decrypted), mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        printf("Decrypted data: %.*s\n", (int) olen, decrypted);
    } else if (choice == 3) {
        // Generate RSA Key Pair
        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
        mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

        ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_SIZE, EXPONENT);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        unsigned char public_key[16000];
        ret = mbedtls_pk_write_pubkey_pem(&pk, public_key, sizeof(public_key));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }
        printf("RSA Public Key:\n%s\n", public_key);

        FILE *file = fopen("public_key.pem", "wb");
        if (file == NULL) {
            perror("Error opening file to save public key");
            return;
        }

        fwrite(public_key, 1, strlen((char *)public_key), file);
        fclose(file);

        unsigned char private_key[16000];
        ret = mbedtls_pk_write_key_pem(&pk, private_key, sizeof(private_key));
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }
        printf("RSA Private Key:\n%s\n", private_key);

        file = fopen("private_key.pem", "wb");
        if (file == NULL) {
            perror("Error opening file to save private key");
            return;
        }

        fwrite(private_key, 1, strlen((char *)private_key), file);
        fclose(file);

        printf("RSA Private Key saved to private_key.pem\n");

    } else if (choice == 4) {
        // Digital Signature
        int use_stored_key = 0;
        char private_key_file[256];
        printf("Do you want to use the private key stored in the folder (private_key.pem) or another key? (1 for stored, 2 for another): ");
        scanf("%d", &use_stored_key);
        getchar(); // consume newline character

        if (use_stored_key == 1) {
            strcpy(private_key_file, "private_key.pem");
        } else if (use_stored_key == 2) {
            printf("Enter the path to the RSA private key file: ");
            fgets(private_key_file, sizeof(private_key_file), stdin);
            private_key_file[strcspn(private_key_file, "\n")] = 0;
        } else {
            printf("Invalid choice.\n");
            return;
        }

        FILE *file = fopen(private_key_file, "rb");
        if (file == NULL) {
            perror("Error opening private key file");
            return;
        }

        fseek(file, 0, SEEK_END);
        long private_key_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *private_key_pem = malloc(private_key_len + 1);
        fread(private_key_pem, 1, private_key_len, file);
        private_key_pem[private_key_len] = '\0';
        fclose(file);

        ret = mbedtls_pk_parse_key(&pk, (unsigned char *) private_key_pem, strlen(private_key_pem) + 1, NULL, 0);
        free(private_key_pem);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        char input[245];
        printf("Enter a message to sign (max 245 bytes): ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;

        unsigned char hash[32];
        ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (unsigned char *) input, strlen(input), hash);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        // Save the hash value to hash_value.bin
        FILE *hash_file = fopen("hash_value.bin", "wb");
        if (hash_file == NULL) {
            perror("Error opening file to save hash value");
            return;
        }
        fwrite(hash, 1, sizeof(hash), hash_file);
        fclose(hash_file);
        printf("Hash value saved to hash_value.bin\n");

        unsigned char signature[BUF_SIZE];
        size_t sig_len;
        ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        printf("Digital signature (hex): ");
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");

    } else if (choice == 5) {
        // Verify Digital Signature
        int use_stored_key = 0;
        int use_stored_hash = 0;
        char public_key_file[256];
        char hash_file_path[256];
        printf("Do you want to use the public key stored in the folder (public_key.pem) or another key? (1 for stored, 2 for another): ");
        scanf("%d", &use_stored_key);
        getchar(); // consume newline character

        if (use_stored_key == 1) {
            strcpy(public_key_file, "public_key.pem");
        } else if (use_stored_key == 2) {
            printf("Enter the path to the RSA public key file: ");
            fgets(public_key_file, sizeof(public_key_file), stdin);
            public_key_file[strcspn(public_key_file, "\n")] = 0;
        } else {
            printf("Invalid choice.\n");
            return;
        }

        FILE *file = fopen(public_key_file, "rb");
        if (file == NULL) {
            perror("Error opening public key file");
            return;
        }

        fseek(file, 0, SEEK_END);
        long public_key_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *public_key_pem = malloc(public_key_len + 1);
        fread(public_key_pem, 1, public_key_len, file);
        public_key_pem[public_key_len] = '\0';
        fclose(file);

        ret = mbedtls_pk_parse_public_key(&pk, (unsigned char *) public_key_pem, strlen(public_key_pem) + 1);
        free(public_key_pem);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            return;
        }

        printf("Do you want to use the hash value stored in the folder (hash_value.bin) or another hash file? (1 for stored, 2 for another): ");
        scanf("%d", &use_stored_hash);
        getchar(); // consume newline character

        if (use_stored_hash == 1) {
            strcpy(hash_file_path, "hash_value.bin");
        } else if (use_stored_hash == 2) {
            printf("Enter the path to the hash value file: ");
            fgets(hash_file_path, sizeof(hash_file_path), stdin);
            hash_file_path[strcspn(hash_file_path, "\n")] = 0;
        } else {
            printf("Invalid choice.\n");
            return;
        }

        FILE *hash_file = fopen(hash_file_path, "rb");
        if (hash_file == NULL) {
            perror("Error opening hash file");
            return;
        }

        unsigned char hash[32];
        if (fread(hash, 1, sizeof(hash), hash_file) != sizeof(hash)) {
            perror("Error reading hash file");
            fclose(hash_file);
            return;
        }
        fclose(hash_file);

        char signature_hex[BUF_SIZE * 2];
        printf("Enter the digital signature (as hex, max 512 characters): ");
        fgets(signature_hex, sizeof(signature_hex), stdin);
        signature_hex[strcspn(signature_hex, "\n")] = 0;

        size_t sig_len = strlen(signature_hex) / 2;
        unsigned char *signature_bytes = malloc(sig_len);
        if (signature_bytes == NULL) {
            perror("Memory allocation failed");
            return;
        }

        // Convert hex signature to raw bytes
        for (size_t i = 0; i < sig_len; i++) {
            sscanf(&signature_hex[i * 2], "%2hhx", &signature_bytes[i]);
        }

        ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature_bytes, sig_len);
        free(signature_bytes);
        if (ret != 0) {
            handle_mbedtls_error(ret);
            printf("Signature verification failed.\n");
            return;
        }

        printf("Signature verification successful.\n");

    } else {
        printf("Invalid choice.\n");
    }

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}


int main() {
    while (1) {
        printf("Choose an operation:\n");
        printf("1. SHA-256 Hash\n");
        printf("2. RSA Encrypt/Decrypt\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        int choice;
        scanf("%d", &choice);
        getchar(); // consume newline character

        switch (choice) {
            case 1:
                sha256_hash();
                break;
            case 2:
                rsa_encrypt_decrypt();
                break;
            case 3:
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }
    return 0;
}
