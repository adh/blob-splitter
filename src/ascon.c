#include "ascon.h"
#include <string.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint8_t round_constants[16] = {
    0x3c, 0x2d, 0x1e, 0x0f,
    0xf0, 0xe1, 0xd2, 0xc3,
    0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b
};

void ascon_permute(AsconState* state, unsigned rounds) {
    for (int r = 0; r < rounds; r++) {
        // Add round constant
        state->v[2] ^= round_constants[16 - rounds + r];
        
        /* s-box layer */
        state->v[0] ^= state->v[4];
        state->v[4] ^= state->v[3];
        state->v[2] ^= state->v[1];

        uint64_t t[5];
        t[0] = state->v[0] ^ (~state->v[1] & state->v[2]);
        t[2] = state->v[2] ^ (~state->v[3] & state->v[4]);
        t[4] = state->v[4] ^ (~state->v[0] & state->v[1]);
        t[1] = state->v[1] ^ (~state->v[2] & state->v[3]);
        t[3] = state->v[3] ^ (~state->v[4] & state->v[0]);
        t[1] ^= t[0];
        t[3] ^= t[2];
        t[0] ^= t[4];

        /* linear layer */
        state->v[2] = t[2] ^ ROR(t[2], 6 - 1);
        state->v[3] = t[3] ^ ROR(t[3], 17 - 10);
        state->v[4] = t[4] ^ ROR(t[4], 41 - 7);
        state->v[0] = t[0] ^ ROR(t[0], 28 - 19);
        state->v[1] = t[1] ^ ROR(t[1], 61 - 39);
        state->v[2] = t[2] ^ ROR(state->v[2], 1);
        state->v[3] = t[3] ^ ROR(state->v[3], 10);
        state->v[4] = t[4] ^ ROR(state->v[4], 7);
        state->v[0] = t[0] ^ ROR(state->v[0], 19);
        state->v[1] = t[1] ^ ROR(state->v[1], 39);
        state->v[2] = ~state->v[2];
    }
}

void ascon_aead_init(AsconAeadState* state, uint8_t key[16], uint8_t nonce[16]) {
    state->state.v[0] = 0x00001000808c0001ULL;

    state->key[0] = 0;
    state->key[1] = 0;
    for (size_t i = 0; i < 8; i++) {
        state->key[0] |= ((uint64_t)key[i]) << (i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->key[1] |= ((uint64_t)key[i + 8]) << (i * 8);
    }
    state->state.v[1] = state->key[0];
    state->state.v[2] = state->key[1];
    state->state.v[3] = 0;
    state->state.v[4] = 0;
    for (size_t i = 0; i < 8; i++) {
        state->state.v[3] |= ((uint64_t)nonce[i]) << (i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->state.v[4] |= ((uint64_t)nonce[i + 8]) << (i * 8);
    }

    ascon_permute(&state->state, 12);
    state->state.v[3] ^= state->key[0];
    state->state.v[4] ^= state->key[1];
    state->index = 0;
}
void ascon_aead_ad_block(AsconAeadState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        state->state.v[0] ^= ((uint64_t)block[i]) << (i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        state->state.v[1] ^= ((uint64_t)block[i + 8]) << (i * 8);
    }
    ascon_permute(&state->state, 8);
    state->index = 0;
}
void ascon_aead_ad_end(AsconAeadState* state) {
    if (state->index > 0) {
        if (state->index < 8) {
            state->state.v[0] ^= (uint64_t)0x01ULL << ((state->index % 8) * 8);
        } else {
            state->state.v[1] ^= (uint64_t)0x01ULL << ((state->index % 8) * 8);
        }
        ascon_permute(&state->state, 8);
    }
    state->state.v[4] ^= 0x8000000000000000ULL;
    state->index = 0;
}
void ascon_aead_encrypt_block(AsconAeadState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        state->state.v[0] ^= ((uint64_t)block[i]) << (i * 8);
        block[i] = (state->state.v[0] >> (i * 8)) & 0xFF;
    }
    for (size_t i = 0; i < 8; i++) {
        state->state.v[1] ^= ((uint64_t)block[i + 8]) << (i * 8);
        block[i + 8] = (state->state.v[1] >> (i * 8)) & 0xFF;
    }
    ascon_permute(&state->state, 8);
    state->index = 0;
}
void ascon_aead_decrypt_block(AsconAeadState* state, uint8_t block[16]) {
    for (size_t i = 0; i < 8; i++) {
        uint8_t c = block[i];
        block[i] ^= (state->state.v[0] >> (i * 8)) & 0xFF;
        state->state.v[0] &= ~((uint64_t)0xFFULL << (i * 8));
        state->state.v[0] |= ((uint64_t)c) << (56 - i * 8);
    }
    for (size_t i = 0; i < 8; i++) {
        uint8_t c = block[i + 8];
        block[i + 8] ^= (state->state.v[1] >> (i * 8)) & 0xFF;
        state->state.v[1] &= ~((uint64_t)0xFFULL << (i * 8));
        state->state.v[1] |= ((uint64_t)c) << (i * 8);
    }
    ascon_permute(&state->state, 8);
    state->index = 0;
}
void ascon_aead_finish(AsconAeadState* state, uint8_t tag[16]) {
    // padding
    state->state.v[state->index / 8] ^= (uint64_t)0x01ULL << ((state->index % 8) * 8);
    state->index = 0;
    state->state.v[2] ^= state->key[0];
    state->state.v[3] ^= state->key[1];
    ascon_permute(&state->state, 12);
    state->state.v[3] ^= state->key[0];
    state->state.v[4] ^= state->key[1];
    for (size_t i = 0; i < 8; i++) {
        tag[i] = (state->state.v[3] >> (i * 8)) & 0xFF;
    }
    for (size_t i = 0; i < 8; i++) {
        tag[i + 8] = (state->state.v[4] >> (i * 8)) & 0xFF;
    }
}

void ascon_aead_ad_bytes(AsconAeadState* state, uint8_t* data, size_t len) {
    while (len > 0) {
        state->state.v[state->index / 8] ^= ((uint64_t)(*data)) << ((state->index % 8) * 8);
        state->index++;
        data++;
        len--;
        if (state->index == 16) {
            ascon_permute(&state->state, 8);
            state->index = 0;
        }
    }
}
void ascon_aead_encrypt_bytes(AsconAeadState* state, uint8_t* buf, size_t len) {
    while (len > 0) {
        state->state.v[state->index / 8] ^= ((uint64_t)(*buf)) << ((state->index % 8) * 8);
        *buf = (state->state.v[state->index / 8] >> ((state->index % 8) * 8)) & 0xFF;
        state->index++;
        buf++;
        len--;
        if (state->index == 16) {
            ascon_permute(&state->state, 8);
            state->index = 0;
        }
    }
}
void ascon_aead_decrypt_bytes(AsconAeadState* state, uint8_t* buf, size_t len) {
    while (len > 0) {
        uint8_t c = *buf;
        *buf ^= (state->state.v[state->index / 8] >> ((state->index % 8) * 8)) & 0xFF;
        state->state.v[state->index / 8] &= ~((uint64_t)0xFFULL << ((state->index % 8) * 8));
        state->state.v[state->index / 8] |= ((uint64_t)c) << ((state->index % 8) * 8);
        state->index++;
        buf++;
        len--;
        if (state->index == 16) {
            ascon_permute(&state->state, 8);
            state->index = 0;
        }
    }
}

void ascon_hash_init(AsconHashState* state) {
    state->state.v[0] = 0x0000080100cc0002ULL;
    state->state.v[1] = 0;
    state->state.v[2] = 0;
    state->state.v[3] = 0;
    state->state.v[4] = 0;
    state->index = 0;
    ascon_permute(&state->state, 12);
}
void ascon_hash_update(AsconHashState* state, uint8_t* data, size_t len) {
    while (len > 0) {
        state->state.v[state->index / 8] ^= ((uint64_t)(*data)) << ((state->index % 8) * 8);
        state->index++;
        data++;
        len--;
        if (state->index == 8) {
            ascon_permute(&state->state, 12);
            state->index = 0;
        }
    }
}
void ascon_hash_finish(AsconHashState* state, uint8_t hash[32]) {
    // padding
    state->state.v[state->index / 8] ^= (uint64_t)0x01ULL << ((state->index % 8) * 8);
    state->index = 0;
    ascon_permute(&state->state, 12);
    for (size_t i = 0; i < 8; i++) {
        hash[i] = (state->state.v[0] >> (i * 8)) & 0xFF;
    }
    ascon_permute(&state->state, 12);
    for (size_t i = 0; i < 8; i++) {
        hash[i + 8] = (state->state.v[0] >> (i * 8)) & 0xFF;
    }
    ascon_permute(&state->state, 12);
    for (size_t i = 0; i < 8; i++) {
        hash[i + 16] = (state->state.v[0] >> (i * 8)) & 0xFF;
    }
    ascon_permute(&state->state, 12);
    for (size_t i = 0; i < 8; i++) {
        hash[i + 24] = (state->state.v[0] >> (i * 8)) & 0xFF;
    }
}

void ascon_xof_init(AsconXofState* state) {
    state->state.v[0] = 0x0000080000cc0003ULL;
    state->state.v[1] = 0;
    state->state.v[2] = 0;
    state->state.v[3] = 0;
    state->state.v[4] = 0;
    state->index = 0;
    ascon_permute(&state->state, 12);
}
void ascon_cxof_init(AsconXofState* state, uint8_t* data, size_t len) {
    state->state.v[0] = 0x0000080000cc0004ULL;
    state->state.v[1] = 0;
    state->state.v[2] = 0;
    state->state.v[3] = 0;
    state->state.v[4] = 0;
    state->index = 0;
    ascon_permute(&state->state, 12);
    uint8_t z0[8];
    z0[0] = len & 0xFF;
    z0[1] = (len >> 8) & 0xFF;
    z0[2] = (len >> 16) & 0xFF;
    z0[3] = (len >> 24) & 0xFF;
    z0[4] = (len >> 32) & 0xFF;
    z0[5] = (len >> 40) & 0xFF;
    z0[6] = (len >> 48) & 0xFF;
    z0[7] = (len >> 56) & 0xFF;
    ascon_xof_absorb(state, z0, 8);
    ascon_xof_absorb(state, data, len);
    ascon_xof_finalize(state);
}
void ascon_xof_absorb(AsconXofState* state, uint8_t* data, size_t len) {
    if (state->squeezing) { /* nonstandard: permit absorbing after squeezing */
        ascon_permute(&state->state, 12);
        state->squeezing = 0;
        state->index = 0;
    }
    while (len > 0) {
        state->state.v[state->index / 8] ^= ((uint64_t)(*data)) << ((state->index % 8) * 8);
        state->index++;
        data++;
        len--;
        if (state->index == 8) {
            ascon_permute(&state->state, 12);
            state->index = 0;
        }
    }
}
void ascon_xof_finalize(AsconXofState* state) {
    // padding
    state->state.v[state->index / 8] ^= (uint64_t)0x01ULL << ((state->index % 8) * 8);
    state->index = 0;
    state->squeezing = 1;
    ascon_permute(&state->state, 12);
}
void ascon_xof_squeeze(AsconXofState* state, uint8_t* out, size_t len) {
    if (!state->squeezing) {
        ascon_xof_finalize(state);
    }
    while (len > 0) {
        *out = (state->state.v[state->index / 8] >> ((state->index % 8) * 8)) & 0xFF;
        state->index++;
        out++;
        len--;
        if (state->index == 8) {
            ascon_permute(&state->state, 12);
            state->index = 0;
        }
    }
}