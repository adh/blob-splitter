#ifndef H__ASCON_H__
#define H__ASCON_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AsconState_s {
    uint64_t v[5];
} AsconState;

typedef struct AsconAeadState_s {
    AsconState state;
    uint64_t key[2];
    size_t index;
} AsconAeadState;

void ascon_permute(AsconState* state, unsigned rounds);

void ascon_aead_init(AsconAeadState* state, uint8_t key[16], uint8_t nonce[16]);
void ascon_aead_ad_block(AsconAeadState* state, uint8_t block[16]);
void ascon_aead_ad_end(AsconAeadState* state);
void ascon_aead_encrypt_block(AsconAeadState* state, uint8_t block[16]);
void ascon_aead_decrypt_block(AsconAeadState* state, uint8_t block[16]);
void ascon_aead_finish(AsconAeadState* state, uint8_t tag[16]);

void ascon_aead_ad_bytes(AsconAeadState* state, uint8_t* data, size_t len);
void ascon_aead_encrypt_bytes(AsconAeadState* state, uint8_t* buf, size_t len);
void ascon_aead_decrypt_bytes(AsconAeadState* state, uint8_t* buf, size_t len);

typedef struct AsconHashState_s {
    AsconState state;
    size_t index;
} AsconHashState;

void ascon_hash_init(AsconHashState* state);
void ascon_hash_update(AsconHashState* state, uint8_t* data, size_t len);
void ascon_hash_finish(AsconHashState* state, uint8_t hash[32]);

typedef struct AsconXofState_s {
    AsconState state;
    size_t index;
    bool squeezing;
} AsconXofState;

void ascon_xof_init(AsconXofState* state);
void ascon_cxof_init(AsconXofState* state, uint8_t* bytes, size_t len);
void ascon_xof_absorb(AsconXofState* state, uint8_t* data, size_t len);
void ascon_xof_finalize(AsconXofState* state);
void ascon_xof_squeeze(AsconXofState* state, uint8_t* out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif