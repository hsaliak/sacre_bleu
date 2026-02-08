#include <sys/syscall.h>

void _start(void) { // NOLINT(bugprone-reserved-identifier)
    // write(1, "hello\n", 6)
    __asm__ __volatile__ (
        "movq $1, %%rax\n"
        "movq $1, %%rdi\n"
        "lea msg(%%rip), %%rsi\n"
        "movq $6, %%rdx\n"
        "syscall\n"
        // exit(0)
        "movq $60, %%rax\n"
        "movq $0, %%rdi\n"
        "syscall\n"
        "msg: .ascii \"hello\\n\""
        :
        :
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
}
