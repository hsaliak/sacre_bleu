#include <sys/syscall.h>

void _start() {
    // getppid (Forbidden)
    long ret;
    asm volatile (
        "movq $110, %%rax\n"
        "syscall"
        : "=a" (ret)
        :
        : "rcx", "r11", "memory"
    );

    // exit(0)
    asm volatile (
        "movq $60, %%rax\n"
        "movq $0, %%rdi\n"
        "syscall"
        :
        :
        : "rax", "rdi", "rcx", "r11", "memory"
    );
}
