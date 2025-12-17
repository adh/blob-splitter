#ifndef H__RANDOM_H__
#define H__RANDOM_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ascon.h"

bool get_random_bytes(uint8_t* buffer, size_t length);

typedef struct RandomGenerator_s {
    AsconXofState xof_state;
} RandomGenerator;

void rng_init(RandomGenerator* rng, uint8_t seed[16]);
void rng_get_bytes(RandomGenerator* rng, uint8_t* buffer, size_t length);

#endif // H__RANDOM_H__
