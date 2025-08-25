/*
 * Simple demo program using ML-DSA reference implementation
 */

#include <stdio.h>
#include <stdint.h>
#define MLDSA_MODE 3   
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #include <fcntl.h>
  #include <unistd.h>
#endif

#include "api.h"   

// Minimal cross-platform randombytes() implementation

void randombytes(uint8_t *out, size_t outlen) {
#ifdef _WIN32
    // Windows CNG API
    if (BCryptGenRandom(NULL, out, (ULONG)outlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, "BCryptGenRandom failed\n");
        exit(1);
    }
#else
    // macOS/Linux: use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        exit(1);
    }
    size_t read_bytes = 0;
    while (read_bytes < outlen) {
        ssize_t r = read(fd, out + read_bytes, outlen - read_bytes);
        if (r <= 0) {
            fprintf(stderr, "Failed to read /dev/urandom\n");
            close(fd);
            exit(1);
        }
        read_bytes += (size_t)r;
    }
    close(fd);
#endif
}


// Demo: generate keypair, sign, and verify

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    uint8_t message[] = "Hello ML-DSA!";
    size_t mlen = strlen((char *)message);

    uint8_t sig[CRYPTO_BYTES];
    size_t siglen;

    // Generate keypair
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Keypair generation failed\n");
        return 1;
    }
    printf("Keypair generated.\n");

    // Sign message
    if (crypto_sign_signature(sig, &siglen, message, mlen,NULL,0, sk) != 0) {
        fprintf(stderr, "Signing failed\n");
        return 1;
    }
    printf("Message signed. Signature length = %zu bytes.\n", siglen);

    // Verify signature
    if (crypto_sign_verify(sig, siglen, message, mlen,NULL,0, pk) != 0) {
        printf("Signature verification FAILED.\n");
    } else {
        printf("Signature verification SUCCESS.\n");
    }

    return 0;
}
