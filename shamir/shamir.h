#ifndef H__SHAMIR_H__
#define H__SHAMIR_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ShamirStatus_e {
    SHAMIR_SUCCESS = 0,
    SHAMIR_ERROR_INVALID_PARAMETERS,
    SHAMIR_ERROR_INSUFFICIENT_SHARES,
    SHAMIR_ERROR_MEMORY_ALLOCATION,
    SHAMIR_ERROR_UNKNOWN
} ShamirStatus;

typedef void (*ShamirRng_get_bytes)(void* rng, uint8_t* buffer, size_t length);

typedef struct ShamirRng_s {
    void* state;
    ShamirRng_get_bytes get_bytes;
} ShamirRng;

// Shamir's Secret Sharing functions
extern ShamirStatus shamir_split(
    const uint8_t *secret, size_t secret_len, 
    size_t num_shares, size_t threshold,
    ShamirRng* rng,
    uint8_t ***out_shares
);
extern ShamirStatus shamir_reconstruct(
    const uint8_t **shares, 
    size_t num_shares, 
    size_t secret_len, 
    uint8_t *out_secret
);

#ifdef __cplusplus
}
#endif

#endif // H__SHAMIR_H__