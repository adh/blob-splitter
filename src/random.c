#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>
#endif

bool get_random_bytes(uint8_t* buffer, size_t length) {
    getentropy(buffer, length);
    return true;
}

void rng_init(RandomGenerator* rng, uint8_t seed[16]) {
    ascon_cxof_init(&rng->xof_state, (uint8_t*)"RNG", 3);
    ascon_xof_absorb(&rng->xof_state, seed, 16);
    ascon_xof_finalize(&rng->xof_state);
}
void rng_get_bytes(RandomGenerator* rng, uint8_t* buffer, size_t length) {
    ascon_xof_squeeze(&rng->xof_state, buffer, length);
}