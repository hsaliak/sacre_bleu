#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    printf("Testing bleu-loader...\n");
    printf("My PID is: %d\n", getpid());
    
    // Test a syscall
    syscall(SYS_getpid);
    
    return 0;
}
