#include "shamir.h"
#include "random.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main() {
    const uint8_t secret[] = { 'H', 'e', 'l', 'l', 'o' };
    size_t secret_len = sizeof(secret);
    size_t num_shares = 5;
    size_t threshold = 3;
    uint8_t **shares = NULL;
    uint8_t random_seed[16];
    RandomGenerator rng;

    get_random_bytes(random_seed, sizeof(random_seed));
    rng_init(&rng, random_seed);

    ShamirRng srng;
    srng.state = &rng;
    srng.get_bytes = (ShamirRng_get_bytes)rng_get_bytes;
    ShamirStatus status = shamir_split(secret, secret_len, num_shares, threshold, &srng, &shares);
    if (status != SHAMIR_SUCCESS) {
        printf("Error splitting secret: %d\n", status);
        return 1;
    }

    printf("Shares:\n");
    for (size_t i = 0; i < num_shares; i++) {
        printf("Share %zu: ", i + 1);
        for (size_t j = 0; j < secret_len + 1; j++) {
            printf("%02X ", shares[i][j]);
        }
        printf("\n");
    }

    const uint8_t *selected_shares[3];
    selected_shares[0] = shares[1];
    selected_shares[1] = shares[3];
    selected_shares[2] = shares[4];

    uint8_t reconstructed_secret[secret_len];
    status = shamir_reconstruct(selected_shares, threshold, secret_len, reconstructed_secret);
    if (status != SHAMIR_SUCCESS) {
        printf("Error reconstructing secret: %d\n", status);
        for (size_t i = 0; i < num_shares; i++) {
            free(shares[i]);
        }
        free(shares);
        return 1;
    }
    printf("Reconstructed Secret: ");
    for (size_t i = 0; i < secret_len; i++) {
        printf("%c", reconstructed_secret[i]);
    }
    printf("\n");
    for (size_t i = 0; i < num_shares; i++) {
        free(shares[i]);
    }
    free(shares);
    return 0;
}