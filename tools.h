#ifndef _TOOLS_H_
#define _TOOLS_H_

#include <stdio.h>
#include <stdint.h>

#define CACHE_PAGE      4096            // 2^12 -> shl $12, %rax

#define flush_pipeline                      \
    asm volatile(                           \
        "cpuid\n"                           \
        "mfence\n"                          \
        :                                   \
        :                                   \
        : "rax","rbx","rcx","rdx","memory");

typedef struct {
    uint8_t unused_1[CACHE_PAGE];       // Memory separator
    union {
        size_t x;                       // Valid array index for speculative storage (for Spectre V4)
        uint8_t unused_2[CACHE_PAGE];   // Memory separator
    };
    union {
        size_t indices_size;            // Indices array size (for Spectre V1/V4)
        uint8_t unused_3[CACHE_PAGE];   // Memory separator
    };
    union {
        uint8_t indices[16];            // Array with valid indices (for Spectre V1/V4)
        uint8_t unused_4[CACHE_PAGE];   // Memory separator
    };
    uint8_t table[256 * CACHE_PAGE];    // Array for Flush+Reload tests
    uint8_t unused_5[CACHE_PAGE];       // Memory separator
} memory_buffer_t;

extern char *secret;

extern memory_buffer_t buffer;

typedef size_t (*exploit_handler)(size_t address, int tries);

int execute(void *addres, size_t len, int tries, exploit_handler exploit);

#endif
