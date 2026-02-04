#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char* argv[]) {
    if (argc > 1) {
        // We use a simple loop to check the argument without using std::string
        if (argv[1][0] == 'v') { // "violate_seccomp"
            syscall(SYS_getppid);
            _exit(0);
        }
    }
    // Default success path
    syscall(SYS_getpid);
    _exit(0);
}
