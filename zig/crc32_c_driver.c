// crc32_c_driver.c — Tiny C driver that reads stdin and prints CRC32 using dafsa_crc32.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "../dafsa_internal.h"

int main(void) {
    // Read all stdin into a buffer
    size_t cap = 1024 * 1024 * 16; // 16MB initial cap
    uint8_t *buf = malloc(cap);
    if (!buf) {
        fprintf(stderr, "out of memory\n");
        return 2;
    }
    size_t len = 0;
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len == cap) {
            cap *= 2;
            uint8_t *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                fprintf(stderr, "out of memory\n");
                return 2;
            }
            buf = tmp;
        }
    }
    if (n < 0) {
        free(buf);
        perror("read");
        return 2;
    }

    uint32_t crc = crc32_compute(buf, len);
    printf("%08x\n", crc);

    free(buf);
    return 0;
}
