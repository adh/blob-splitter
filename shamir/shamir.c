#include <shamir/shamir.h>
#include <stdlib.h>
#include <string.h>

/* 
 * XTEA-based RNG for generating random coefficients so as to make the
 * implementation self-contained.
 */

typedef struct XteaRng_s {
    uint8_t buffer[8];
    size_t index;
    uint64_t counter;
    uint32_t key[4];
} XteaRng;

static void xtea_encrypt_block(XteaRng *rng, uint8_t block[8]) {
    uint32_t v0 = ((uint32_t *)block)[0], v1 = ((uint32_t *)block)[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;
    for (size_t i = 0; i < 32; i++) {
        v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + rng->key[sum & 3]);
        sum += delta;
        v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + rng->key[(sum >> 11) & 3]);
    }
    ((uint32_t *)block)[0] = v0;
    ((uint32_t *)block)[1] = v1;
}

static void xtea_rng_init(XteaRng *rng, const uint8_t seed[16]) {
    memcpy(rng->key, seed, 16);
    rng->index = 8;
    memset(rng->buffer, 0, 8);
    rng->counter = 0;
    xtea_encrypt_block(rng, rng->buffer);
}

static uint8_t gf256_rand(XteaRng *rng) {
    if (rng->index >= 8) {
        // Generate a new block
        for (size_t i = 0; i < 8; i++) {
            rng->buffer[i] = (rng->counter >> (i * 8)) & 0xFF;
        }
        rng->counter++;
        xtea_encrypt_block(rng, rng->buffer);
        rng->index = 0;
    }
    return rng->buffer[rng->index++];
}

static uint8_t gf256_add(uint8_t a, uint8_t b) {
    return a ^ b;
}
static uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b; // reduce by AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

static uint8_t gf256_pow(uint8_t a, uint8_t exp) {
    uint8_t result = 1;
    while (exp) {
        if (exp & 1) result = gf256_mul(result, a);
        a = gf256_mul(a, a);
        exp >>= 1;
    }
    return result;
}
static uint8_t gf256_inv(uint8_t a) {
    if (a == 0) return 0; // no inverse for 0; caller should not ask for it
    // a^(254) gives multiplicative inverse in GF(2^8) (order 255)
    return gf256_pow(a, 254);
}

static uint8_t gf256_poly_eval(const uint8_t *poly, size_t degree, uint8_t x) {
    // Horner's rule: evaluate poly[degree]*x^degree + ... + poly[0]
    uint8_t result = poly[degree];
    for (size_t i = degree; i-- > 0; ) {
        result = gf256_mul(result, x);
        result = gf256_add(result, poly[i]);
    }
    return result;
}

ShamirStatus shamir_split(
    const uint8_t *secret, size_t secret_len, 
    size_t num_shares, size_t threshold,
    uint8_t random_seed[16],
    uint8_t ***out_shares
) {
    if (!secret || secret_len == 0 || num_shares < threshold || threshold == 0 || !out_shares) {
        return SHAMIR_ERROR_INVALID_PARAMETERS;
    }

    XteaRng rng;
    xtea_rng_init(&rng, random_seed);

    uint8_t **shares = (uint8_t **)malloc(num_shares * sizeof(uint8_t *));
    if (!shares) {
        return SHAMIR_ERROR_MEMORY_ALLOCATION;
    }
    for (size_t i = 0; i < num_shares; i++) {
        shares[i] = (uint8_t *)malloc(secret_len + 1);
        if (!shares[i]) {
            for (size_t j = 0; j < i; j++) free(shares[j]);
            free(shares);
            return SHAMIR_ERROR_MEMORY_ALLOCATION;
        }
        shares[i][0] = (uint8_t)(i + 1);
    }

    for (size_t byte_idx = 0; byte_idx < secret_len; byte_idx++) {
        uint8_t *poly = (uint8_t *)malloc(threshold * sizeof(uint8_t));
        if (!poly) {
            for (size_t i = 0; i < num_shares; i++) free(shares[i]);
            free(shares);
            return SHAMIR_ERROR_MEMORY_ALLOCATION;
        }
        poly[0] = secret[byte_idx];
        for (size_t i = 1; i < threshold; i++) {
            poly[i] = gf256_rand(&rng);
        }
        for (size_t share_idx = 0; share_idx < num_shares; share_idx++) {
            shares[share_idx][byte_idx + 1] = gf256_poly_eval(poly, threshold - 1, shares[share_idx][0]);
        }
        free(poly);
    }

    *out_shares = shares;
    return SHAMIR_SUCCESS;
}
ShamirStatus shamir_reconstruct(
    const uint8_t **shares, 
    size_t num_shares, 
    size_t secret_len, 
    uint8_t *out_secret
) {
    if (!shares || num_shares == 0 || secret_len == 0 || !out_secret) {
        return SHAMIR_ERROR_INVALID_PARAMETERS;
    }

    for (size_t byte_idx = 0; byte_idx < secret_len; byte_idx++) {
        uint8_t secret_byte = 0;
        for (size_t i = 0; i < num_shares; i++) {
            uint8_t xi = shares[i][0];
            uint8_t yi = shares[i][byte_idx + 1];
            uint8_t li = 1;
            for (size_t j = 0; j < num_shares; j++) {
                if (i != j) {
                    uint8_t xj = shares[j][0];
                    li = gf256_mul(li, gf256_mul(xj, gf256_inv(gf256_add(xi, xj))));
                }
            }
            secret_byte = gf256_add(secret_byte, gf256_mul(yi, li));
        }
        out_secret[byte_idx] = secret_byte;
    }
    return SHAMIR_SUCCESS;
}