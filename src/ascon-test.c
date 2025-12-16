#include <util/ascon.h>
#include <string.h>
#include <stdio.h>

uint8_t key[16] = {
    0x9e, 0x54, 0x4e, 0xf5, 0xe6, 0x90, 0x77, 0x00,
    0xb6, 0xf4, 0x69, 0xd8, 0xc1, 0x30, 0x9d, 0x91
};
uint8_t nonce[16] = {
    0x75, 0xdd, 0xe1, 0xef, 0x53, 0x5b, 0x52, 0x8a,
    0xf9, 0x19, 0x9a, 0xf1, 0x38, 0xa4, 0x9f, 0x5c
};
uint8_t plaintext[] = "ascon";
uint8_t associated_data[] = "ASCON";

void hexdump(const char* label, const uint8_t* buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(){
    AsconState state;
    ascon_aead_init(&state, key, nonce);
    ascon_aead_ad_bytes(&state, associated_data, sizeof(associated_data) - 1);
    ascon_aead_ad_end(&state);
    uint8_t bytes [5];
    memcpy(bytes, plaintext, 5);
    ascon_aead_encrypt_bytes(&state, bytes, 5);
    uint8_t tag[16];
    ascon_aead_finish(&state, tag);

    hexdump("Ciphertext", bytes, sizeof(bytes));
    hexdump("Tag", tag, sizeof(tag));

    return 0;
}