#include <util/ascon.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

uint8_t key[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
uint8_t nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
uint8_t plaintext[] = "ascon";
char* plaintext2 = "The quick brown fox jumps over the lazy dog";
uint8_t associated_data[] = "ASCON";
char* associated_data2 = "Longer associated data for more complete test";

void hexdump(const char* label, const uint8_t* buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(){
    AsconState state;

    state.v[0] = 0x0000080100cc0002;
    state.v[1] = 0x0000000000000000;
    state.v[2] = 0x0000000000000000;
    state.v[3] = 0x0000000000000000;
    state.v[4] = 0x0000000000000000;
    ascon_permute(&state, 12);
    printf("S0= %016" PRIx64 "\n", state.v[0]);
    printf("S1= %016" PRIx64 "\n", state.v[1]);
    printf("S2= %016" PRIx64 "\n", state.v[2]);
    printf("S3= %016" PRIx64 "\n", state.v[3]);
    printf("S4= %016" PRIx64 "\n", state.v[4]);


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

    ascon_aead_init(&state, key, nonce);
    ascon_aead_ad_bytes(&state, associated_data, sizeof(associated_data) - 1);
    ascon_aead_ad_end(&state);
    uint8_t decrypted[5];
    memcpy(decrypted, bytes, 5);
    ascon_aead_decrypt_bytes(&state, decrypted, 5);
    uint8_t check_tag[16];
    ascon_aead_finish(&state, check_tag);

    hexdump("Decrypted", decrypted, sizeof(decrypted));
    hexdump("Check Tag", check_tag, sizeof(check_tag));

    for (int i = 0; i < 16; i++){
        key[i] = i;
        nonce[i] = i;
    }


    uint8_t* bytes2 = malloc(strlen(plaintext2));
    memcpy(bytes2, plaintext2, strlen(plaintext2));

    ascon_aead_init(&state, key, nonce);
    ascon_aead_ad_bytes(&state, associated_data2, strlen(associated_data2));
    ascon_aead_ad_end(&state);
    ascon_aead_encrypt_bytes(&state, bytes2, strlen(plaintext2));
    printf("index= %zu\n", state.index);
    printf("S0= %016" PRIx64 "\n", state.v[0]);
    printf("S1= %016" PRIx64 "\n", state.v[1]);
    printf("S2= %016" PRIx64 "\n", state.v[2]);
    printf("S3= %016" PRIx64 "\n", state.v[3]);
    printf("S4= %016" PRIx64 "\n", state.v[4]);
    ascon_aead_finish(&state, tag);

    hexdump("Ciphertext", bytes2, strlen(plaintext2));
    hexdump("Tag", tag, sizeof(tag));


    free(bytes2);
    return 0;
}