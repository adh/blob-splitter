#include <util/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

bool get_random_bytes(uint8_t* buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t result = read(fd, buffer, length);
    close(fd);
    return result == (ssize_t)length;
}