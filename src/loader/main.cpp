#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>

#include "src/common/policy.h"

namespace {

// Minimal syscall mapping for demo purposes.
// In a production app, this would be generated from <sys/syscall.h>.
int GetSyscallNr(const std::string& name) {
    static const std::map<std::string, int> syscalls = {
        {"read", SYS_read},
        {"write", SYS_write},
        {"open", SYS_open},
        {"close", SYS_close},
        {"execve", SYS_execve},
        {"exit", SYS_exit},
        {"brk", SYS_brk},
        {"mmap", SYS_mmap},
        {"munmap", SYS_munmap},
        {"mprotect", SYS_mprotect},
        {"rt_sigaction", SYS_rt_sigaction},
        {"rt_sigprocmask", SYS_rt_sigprocmask},
        {"getpid", SYS_getpid},
        {"getuid", SYS_getuid},
        {"getgid", SYS_getgid},
        {"arch_prctl", SYS_arch_prctl},
        {"set_tid_address", SYS_set_tid_address},
        {"exit_group", SYS_exit_group},
        {"fstat", SYS_fstat},
        {"lseek", SYS_lseek},
        {"mmap", SYS_mmap},
        {"munmap", SYS_munmap},
        {"mprotect", SYS_mprotect},
        {"brk", SYS_brk},
        {"rt_sigaction", SYS_rt_sigaction},
        {"rt_sigprocmask", SYS_rt_sigprocmask},
        {"set_robust_list", SYS_set_robust_list},
        {"prlimit64", SYS_prlimit64},
        {"access", SYS_access},
        {"openat", SYS_openat},
        {"fstatfs", SYS_fstatfs},
        {"pread64", SYS_pread64},
        {"getdents64", SYS_getdents64},
        {"ioctl", SYS_ioctl},
        {"fcntl", SYS_fcntl},
    };
    auto it = syscalls.find(name);
    if (it != syscalls.end()) return it->second;
    return -1;
}

bool ApplySeccomp(const std::vector<std::string>& allowed) {
    std::vector<sock_filter> filter = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    };

    // Allow each syscall in the list
    for (const auto& name : allowed) {
        int nr = GetSyscallNr(name);
        if (nr != -1) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(nr), 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    }

    // Default: Kill
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    struct sock_fprog prog;
    prog.len = (unsigned short)filter.size();
    prog.filter = filter.data();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_binary> [args...]" << std::endl;
        return 1;
    }

    std::string target_path = argv[1];

    // 1. Extract policy from binary
    std::string tmp_policy = "/tmp/extracted_policy.bin";
    std::string cmd = "objcopy --dump-section .sacre_policy=" + tmp_policy + " " + target_path + " /dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) {
        std::cerr << "No sacre policy found in " << target_path << " (or objcopy failed)" << std::endl;
        // Optionally continue without policy or fail. 
        // For this demo, let's proceed to exec even if no policy exists.
    }

    // 2. Read and Decode policy
    sacre::policy::Policy policy;
    std::ifstream policy_file(tmp_policy, std::ios::binary);
    if (policy_file.is_open()) {
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(policy_file)),
                                     std::istreambuf_iterator<char>());
        auto result = sacre::policy::Deserialize(buffer.data(), buffer.size());
        if (result.success) {
            policy = std::move(result.value);
        } else {
            std::cerr << "Failed to deserialize policy: " << result.error_message << std::endl;
        }
        policy_file.close();
        unlink(tmp_policy.c_str());
    }

    // 3. Apply Namespaces (Hardening)
    int flags = 0;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kPid)) flags |= CLONE_NEWPID;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kNet)) flags |= CLONE_NEWNET;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kMount)) flags |= CLONE_NEWNS;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kIpc)) flags |= CLONE_NEWIPC;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUts)) flags |= CLONE_NEWUTS;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUser)) flags |= CLONE_NEWUSER;

    if (flags != 0) {
        if (unshare(flags) != 0) {
            perror("unshare");
            std::cerr << "Warning: Failed to apply namespaces (are you root or have CAP_SYS_ADMIN?)" << std::endl;
        }
    }

    // 4. Seccomp (Hardening)
    if (!policy.allowed_syscalls.empty()) {
        // We do this just before exec
    }

    // 5. Fork & Exec
    // If we used CLONE_NEWPID, we need to fork for it to take effect.
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child
        if (!policy.allowed_syscalls.empty()) {
            if (!ApplySeccomp(policy.allowed_syscalls)) {
                return 1;
            }
        }

        char** exec_args = new char*[argc];
        for (int i = 1; i < argc; ++i) {
            exec_args[i-1] = argv[i];
        }
        exec_args[argc-1] = nullptr;

        execv(target_path.c_str(), exec_args);
        perror("execv");
        return 1;
    } else {
        // Parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            std::cerr << "Child killed by signal: " << WTERMSIG(status) << std::endl;
            return 128 + WTERMSIG(status);
        }
        return WEXITSTATUS(status);
    }
}
