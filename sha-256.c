#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"

int main()
{
    mbedtls_sha256_context sha_ctx;
    unsigned char input[] = "Hello, world!"; // Example input data
    unsigned char output[32]; // SHA-256 produces a 32-byte hash

    // Initialize SHA-256 context
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 for SHA-256, 1 for SHA-224

    // Provide data to be hashed
    mbedtls_sha256_update(&sha_ctx, input, strlen((char *)input));

    // Compute the SHA-256 hash
    mbedtls_sha256_finish(&sha_ctx, output);

    // Print the hash in hexadecimal
    printf("SHA-256 Hash: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // Clean up
    mbedtls_sha256_free(&sha_ctx);

    return 0;
}
