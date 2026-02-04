#include <iostream>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    std::cout << "Testing sacre-loader...\n";
    std::cout << "My PID is: " << getpid() << "\n";
    
    // Test a syscall
    syscall(SYS_getpid);
    
    return 0;
}
