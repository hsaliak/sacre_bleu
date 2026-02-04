#include <sys/syscall.h>

void _start(void) { // NOLINT(bugprone-reserved-identifier)
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
