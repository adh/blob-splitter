#ifndef H__ASCON_H__
#define H__ASCON_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AsconState_s {
    uint64_t v[5];
    uint64_t key[2];
    size_t index;
} AsconState;

void ascon_aead_init(AsconState* state, uint8_t key[16], uint8_t nonce[16]);
void ascon_aead_ad_block(AsconState* state, uint8_t block[16]);
void ascon_aead_ad_end(AsconState* state);
void ascon_aead_encrypt_block(AsconState* state, uint8_t block[16]);
void ascon_aead_decrypt_block(AsconState* state, uint8_t block[16]);
void ascon_aead_finish(AsconState* state, uint8_t tag[16]);

void ascon_aead_ad_bytes(AsconState* state, uint8_t* data, size_t len);
void ascon_aead_encrypt_bytes(AsconState* state, uint8_t* buf, size_t len);
void ascon_aead_decrypt_bytes(AsconState* state, uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif