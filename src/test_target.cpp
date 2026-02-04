#include <iostream>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    std::cout << "Testing sacre-loader..." << std::endl;
    
    std::cout << "My PID is: " << getpid() << std::endl;
    
    // Try to call getpid via syscall
    long pid = syscall(SYS_getpid);
    std::cout << "Syscall getpid returned: " << pid << std::endl;

    return 0;
}
