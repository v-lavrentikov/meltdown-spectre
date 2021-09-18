#ifndef _TOOLS_H_
#define _TOOLS_H_

#include <stdio.h>
#include <stdint.h>

#define CACHE_PAGE      4096

#define flush_pipeline                      \
    asm volatile(                           \
        "cpuid\n"                           \
        "mfence\n"                          \
        :                                   \
        :                                   \
        : "rax","rbx","rcx","rdx","memory");

typedef struct {
    uint8_t unused1[CACHE_PAGE];        // Memory separator
    union {
        uint8_t unused2[CACHE_PAGE];    // Memory separator
        size_t x;                       // Valid array index for speculative storage (for Spectre V4)
    };
    union {
        uint8_t unused3[CACHE_PAGE];    // Memory separator
        unsigned int array1_size;       // Array size for misprediction (for Spectre V1)
    };
    union {
        uint8_t unused4[CACHE_PAGE];    // Memory separator
        uint8_t array1[16];             // Array with valid indexes (for Spectre V1/V4)
    };
    uint8_t array2[256 * CACHE_PAGE];   // Array for Flush+Reload tests
    uint8_t unused5[CACHE_PAGE];        // Memory separator
} memory_buffer_t;

extern char *secret;

extern memory_buffer_t buffer;

typedef size_t (*exploit_handler)(size_t address, int tries);

int execute(void *addres, size_t len, int tries, exploit_handler exploit);

#endif
