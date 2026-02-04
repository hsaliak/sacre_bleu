#include <sys/syscall.h>

void _start(void) { // NOLINT(bugprone-reserved-identifier)
    // getppid (Forbidden)
    long ret = 0;
    __asm__ __volatile__ (
        "movq $110, %%rax\n"
        "syscall"
        : "=a" (ret)
        :
        : "rcx", "r11", "memory"
    );

    // exit(0)
    __asm__ __volatile__ (
        "movq $60, %%rax\n"
        "movq $0, %%rdi\n"
        "syscall"
        :
        :
        : "rax", "rdi", "rcx", "r11", "memory"
    );
}
