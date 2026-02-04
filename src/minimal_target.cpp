#include <unistd.h>
#include <sys/syscall.h>

int main() {
    // Minimal target that only uses allowed syscalls
    syscall(SYS_getpid);
    _exit(0);
}
