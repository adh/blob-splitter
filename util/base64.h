#ifndef H__BASE64_H__
#define H__BASE64_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void base64_encode(uint8_t* buf, size_t len, uint8_t**out, size_t* outlen);
bool base64_decode(uint8_t* buf, size_t len, uint8_t**out, size_t* outlen);

#ifdef __cplusplus
}
#endif


#endif