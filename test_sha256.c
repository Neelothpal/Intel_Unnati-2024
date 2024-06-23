#include <stdio.h>
#include <string.h>
#include <mbedtls/sha256.h>

int main() {
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

    return 0;
}
