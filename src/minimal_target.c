#include <sys/syscall.h>

void _start() {
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
