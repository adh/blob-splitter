#ifndef H__RANDOM_H__
#define H__RANDOM_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool get_random_bytes(uint8_t* buffer, size_t length);

#endif // H__RANDOM_H__
