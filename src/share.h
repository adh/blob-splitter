#ifndef H__SHARE_H__
#define H__SHARE_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct Share_s {
    uint8_t identifier[5];
    uint8_t value[17];
} Share;

char* share_to_string(Share* share);
bool string_to_share(const char* str, Share* share);

#endif