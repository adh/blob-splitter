#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

bool get_random_bytes(uint8_t* buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t result = read(fd, buffer, length);
    close(fd);
    return result == (ssize_t)length;
}

void rng_init(RandomGenerator* rng, uint8_t seed[16]) {
    ascon_cxof_init(&rng->xof_state, "RNG", 3);
    ascon_xof_absorb(&rng->xof_state, seed, 16);
    ascon_xof_finalize(&rng->xof_state);
}
void rng_get_bytes(RandomGenerator* rng, uint8_t* buffer, size_t length) {
    ascon_xof_squeeze(&rng->xof_state, buffer, length);
}