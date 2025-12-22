#include "share.h"
#include "ascon.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void encode_base32(const uint8_t input[5], char* output){
    uint64_t buffer = (
        ((uint64_t)input[0] << 32) 
        | ((uint64_t)input[1] << 24) 
        | ((uint64_t)input[2] << 16) 
        | ((uint64_t)input[3] << 8) 
        | (uint64_t)input[4]
    );
    for (int i = 0; i < 8; i++) {
        output[7 - i] = base32_chars[(buffer >> (5 * i)) & 0x1F];
    }
}
static bool decode_base32(const char* input, uint8_t output[5]){
    uint64_t buffer = 0;
    for (int i = 0; i < 8; i++) {
        const char* ptr = strchr(base32_chars, toupper(input[i]));
        if (ptr) {
            buffer |= (ptr - base32_chars) << (5 * (7 - i));
        } else {
            return false;
        }
    }
    output[0] = (buffer >> 32) & 0xFF;
    output[1] = (buffer >> 24) & 0xFF;
    output[2] = (buffer >> 16) & 0xFF;
    output[3] = (buffer >> 8) & 0xFF;
    output[4] = buffer & 0xFF;
    return true;
}

uint32_t crc32(const uint8_t* data, size_t length){
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

char* share_to_string(Share* share){
    char* str = (char*)malloc(54);
    if (str == NULL) {
        return NULL; // Handle memory allocation failure
    }

    str[0] = 'B';
    str[1] = 'S';
    str[2] = 'S';
    str[3] = '1';
    str[4] = '-';

    encode_base32(share->identifier, &str[5]);

    str[13] = '-';
    str[14] = 'I';
    str[15] = "0123456789ABCDEF"[share->value[0] >> 4];
    str[16] = "0123456789ABCDEF"[share->value[0] & 0x0F];
    str[17] = '-';

    uint8_t payload[20];
    memcpy(payload, share->value, 17);

    uint8_t cs_data[22];
    memcpy(cs_data, share->identifier, 5);
    memcpy(cs_data + 5, payload, 17);
    uint32_t checksum = crc32(cs_data, 22);
    payload[17] = (checksum >> 16) & 0xFF;
    payload[18] = (checksum >> 8) & 0xFF;
    payload[19] = checksum & 0xFF;

    encode_base32(payload, &str[18]);
    str[26] = '-';
    encode_base32(payload + 5, &str[27]);
    str[35] = '-';
    encode_base32(payload + 10, &str[36]);
    str[44] = '-';
    encode_base32(payload + 15, &str[45]);
    str[53] = '\0';
    return str;
}

static bool decode_hex(char c, uint8_t* value){
    if (c >= '0' && c <= '9') {
        *value = c - '0';
        return true;
    } else if (c >= 'A' && c <= 'F') {
        *value = c - 'A' + 10;
        return true;
    } else if (c >= 'a' && c <= 'f') {
        *value = c - 'a' + 10;
        return true;
    }
    return false;
}

static void remove_hyphens(char* str){
    char* input = str;
    char* output = str;
    while (*input) {
        if (*input != '-' && *input != ' ') {
            *output++ = *input;
        }
        input++;
    }
    *output = '\0';
}

bool string_to_share(const char* string, Share* share){
    char* str = strdup(string);
    if (str == NULL) {
        return false; // Handle memory allocation failure
    }

    printf("Decoding share string: %s\n", str);
    remove_hyphens(str);

    if (strlen(str) != 47 || str[0] != 'B' || str[1] != 'S' || str[2] != 'S' || str[3] != '1') {
        free(str);
        printf("Invalid share string length %d: %s\n", (int)strlen(str), str);
        return false;
    }

    decode_base32(&str[4], share->identifier);

    if (str[12] != 'I') {

        free(str);
        return false;
    }

    uint8_t high_nibble, low_nibble;
    if (!decode_hex(str[13], &high_nibble) || !decode_hex(str[14], &low_nibble)) {
        free(str);
        return false;
    }

    uint8_t index = (high_nibble << 4) | low_nibble;

    uint8_t payload[20];
    if (!decode_base32(&str[15], payload)) {
        free(str);
        return false;
    }
    if (!decode_base32(&str[23], payload + 5)) {
        free(str);
        return false;
    }
    if (!decode_base32(&str[31], payload + 10)) {
        free(str);
        return false;
    }
    if (!decode_base32(&str[39], payload + 15)) {
        free(str);
        return false;
    }

    if (payload[0] != index) {
        free(str);
        return false;
    }

    uint32_t received_checksum = (payload[17] << 16) | (payload[18] << 8) | payload[19];
    uint8_t cs_data[22];
    memcpy(cs_data, share->identifier, 5);
    memcpy(cs_data + 5, payload, 17);
    uint32_t computed_checksum = crc32(cs_data, 22) & 0xFFFFFF;
    if (received_checksum != computed_checksum) {
        free(str);
        return false;
    }

    memcpy(share->value, payload, 17);
    free(str);
    return true;
}