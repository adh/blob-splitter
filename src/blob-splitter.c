#include "share.h"
#include "shamir.h"
#include "ascon.h"
#include "random.h"
#include <stdlib.h>
#include <stdio.h>

int main(){
    RandomGenerator rng;
    uint8_t seed[16];
    if (!get_random_bytes(seed, sizeof(seed))) {
        fprintf(stderr, "Failed to get random bytes for RNG seed\n");
        return 1;
    }
    rng_init(&rng, seed);

    Share share;
    rng_get_bytes(&rng, share.identifier, 5);
    rng_get_bytes(&rng, share.value, 17);

    char* share_string = share_to_string(&share);
    if (share_string) {
        printf("Share string: %s\n", share_string);
    }

    Share decoded_share;
    if (string_to_share(share_string, &decoded_share)) {
        printf("Decoded share identifier: ");
        for (int i = 0; i < 5; i++) {
            printf("%02X ", decoded_share.identifier[i]);
        }
        printf("\nDecoded share value: ");
        for (int i = 0; i < 17; i++) {
            printf("%02X ", decoded_share.value[i]);
        }
        printf("\n");
    } else {
        printf("Failed to decode share string\n");
    }
    free(share_string);
    return 0;
}