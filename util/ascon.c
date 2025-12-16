#include "ascon.h"
#include <string.h>

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint8_t round_constants[16] = {
    0x3c, 0x2d, 0x1e, 0x0f,
    0xf0, 0xe1, 0xd2, 0xc3,
    0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b
};

static void ascon_permute(AsconState* state, unsigned rounds) {
    for (int r = 0; r < rounds; r++) {
        // Add round constant
        state->v[2] ^= round_constants[16 - rounds + r];
        
        // Substitution layer (S-box)
        state->v[0] ^= state->v[4];
        state->v[4] ^= state->v[3];
        state->v[2] ^= state->v[1];
        uint64_t t[5];

        t[0] = state->v[0] ^ (~state->v[1] & state->v[2]);
        t[1] = state->v[1] ^ (~state->v[2] & state->v[3]);
        t[2] = state->v[4] ^ (~state->v[3] & state->v[4]);
        t[3] = state->v[3] ^ (~state->v[4] & state->v[0]);
        t[4] = state->v[4] ^ (~state->v[0] & state->v[1]);
        t[1] ^= t[0];
        t[3] ^= t[2];
        t[0] ^= t[4];

        // Linear diffusion layer
        state->v[0] = t[0] ^ ROR64(t[0], 19) ^ ROR64(t[0], 28);
        state->v[1] = t[1] ^ ROR64(t[1], 61) ^ ROR64(t[1], 39);
        state->v[2] = t[2] ^ ROR64(t[2], 1)  ^ ROR64(t[2], 6);
        state->v[3] = t[3] ^ ROR64(t[3], 10) ^ ROR64(t[3], 17);
        state->v[4] = t[4] ^ ROR64(t[4], 7)  ^ ROR64(t[4], 41);
    }
}

void ascon_aead_init(AsconState* state, uint8_t key[16], uint8_t nonce[16]) {
    state->v[0] = 0x00001000808c0001ULL;

    state->key[0] = 0;
    state->key[1] = 0;
    for (size_t i = 0; i < 8; i++) {
        state->key[0] |= ((uint64_t)key[i]) << (56 - i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->key[1] |= ((uint64_t)key[i + 8]) << (56 - i * 8);
    }
    state->v[1] = state->key[0];
    state->v[2] = state->key[1];
    state->v[3] = 0;
    state->v[4] = 0;
    for (size_t i = 0; i < 8; i++) {
        state->v[3] |= ((uint64_t)nonce[i]) << (56 - i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->v[4] |= ((uint64_t)nonce[i + 8]) << (56 - i * 8);
    }

    ascon_permute(state, 12);
    state->v[3] ^= state->key[0];
    state->v[4] ^= state->key[1];
    state->index = 0;
}
void ascon_aead_ad_block(AsconState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        state->v[0] ^= ((uint64_t)block[i]) << (56 - i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->v[1] ^= ((uint64_t)block[i + 8]) << (56 - i * 8);
    }
    ascon_permute(state, 8);
    state->index = 0;
}
void ascon_aead_ad_end(AsconState* state) {
    if (state->index > 0) {
        ascon_permute(state, 8);
    }
    state->v[4] ^= 1;
    state->index = 0;
}
void ascon_aead_encrypt_block(AsconState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        state->v[0] ^= ((uint64_t)block[i]) << (56 - i * 8);
        block[i] = (state->v[0] >> (56 - i * 8)) & 0xFF;
    }
    for (size_t i = 0; i < 8; i++) {
        state->v[1] ^= ((uint64_t)block[i + 8]) << (56 - i * 8);
        block[i + 8] = (state->v[1] >> (56 - i * 8)) & 0xFF;
    }
    ascon_permute(state, 8);
    state->index = 0;
}
void ascon_aead_decrypt_block(AsconState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        uint8_t c = block[i];
        block[i] ^= (state->v[0] >> (56 - i * 8)) & 0xFF;
        state->v[0] &= ~((uint64_t)0xFFULL << (56 - i * 8));
        state->v[0] |= ((uint64_t)c) << (56 - i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        uint8_t c = block[i + 8];
        block[i + 8] ^= (state->v[1] >> (56 - i * 8)) & 0xFF;
        state->v[1] &= ~((uint64_t)0xFFULL << (56 - i * 8));
        state->v[1] |= ((uint64_t)c) << (56 - i * 8);
    }
    ascon_permute(state, 8);
    state->index = 0;
}
void ascon_aead_finish(AsconState* state, uint8_t tag[16]) {
    if (state->index > 0) {
        // padding
        state->v[state->index / 8] ^= (uint64_t)0x80ULL << (56 - (state->index % 8) * 8);
        ascon_permute(state, 8);
        state->index = 0;
    }
    state->v[2] ^= state->key[0];
    state->v[3] ^= state->key[1];
    ascon_permute(state, 12);
    state->v[3] ^= state->key[0];
    state->v[4] ^= state->key[1];
    for (size_t i = 0; i < 8; i++) {
        tag[i] = (state->v[3] >> (56 - i * 8)) & 0xFF;
    }
    for (size_t i = 0; i < 8; i++) {
        tag[i + 8] = (state->v[4] >> (56 - i * 8)) & 0xFF;
    }
}

void ascon_aead_ad_bytes(AsconState* state, uint8_t* data, size_t len) {
    while (len > 0) {
        state->v[state->index / 8] ^= ((uint64_t)(*data)) << (56 - (state->index % 8) * 8);
        state->index++;
        data++;
        len--;
        if (state->index == 16) {
            ascon_permute(state, 8);
            state->index = 0;
        }
    }
}
void ascon_aead_encrypt_bytes(AsconState* state, uint8_t* buf, size_t len) {
    while (len > 0) {
        state->v[state->index / 8] ^= ((uint64_t)(*buf)) << (56 - (state->index % 8) * 8);
        *buf = (state->v[state->index / 8] >> (56 - (state->index % 8) * 8)) & 0xFF;
        state->index++;
        buf++;
        len--;
        if (state->index == 16) {
            ascon_permute(state, 8);
            state->index = 0;
        }
    }
}
void ascon_aead_decrypt_bytes(AsconState* state, uint8_t* buf, size_t len) {
    while (len > 0) {
        uint8_t c = *buf;
        *buf ^= (state->v[state->index / 8] >> (56 - (state->index % 8) * 8)) & 0xFF;
        state->v[state->index / 8] &= ~((uint64_t)0xFFULL << (56 - (state->index % 8) * 8));
        state->v[state->index / 8] = ((uint64_t)c) << (56 - (state->index % 8) * 8);
        state->index++;
        buf++;
        len--;
        if (state->index == 16) {
            ascon_permute(state, 8);
            state->index = 0;
        }
    }
}