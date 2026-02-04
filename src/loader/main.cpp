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
#include <cstddef>

#include "src/common/policy.h"

namespace {

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
        {"arch_prctl", SYS_arch_prctl},
        {"set_tid_address", SYS_set_tid_address},
        {"fstat", SYS_fstat},
        {"lseek", SYS_lseek},
        {"set_robust_list", SYS_set_robust_list},
        {"prlimit64", SYS_prlimit64},
        {"getpid", SYS_getpid},
        {"exit_group", SYS_exit_group},
        {"access", SYS_access},
        {"openat", SYS_openat},
        {"fstatfs", SYS_fstatfs},
        {"pread64", SYS_pread64},
        {"getdents64", SYS_getdents64},
        {"ioctl", SYS_ioctl},
        {"fcntl", SYS_fcntl},
        {"writev", SYS_writev},
        {"futex", SYS_futex},
#ifdef __NR_newfstatat
        {"newfstatat", __NR_newfstatat},
#endif
#ifdef __NR_stat
        {"stat", __NR_stat},
#endif
#ifdef __NR_lstat
        {"lstat", __NR_lstat},
#endif
#ifdef __NR_getuid
        {"getuid", __NR_getuid},
#endif
#ifdef __NR_getgid
        {"getgid", __NR_getgid},
#endif
#ifdef __NR_geteuid
        {"geteuid", __NR_geteuid},
#endif
#ifdef __NR_getegid
        {"getegid", __NR_getegid},
#endif
    };
    auto it = syscalls.find(name);
    if (it != syscalls.end()) return it->second;
    return -1;
}

bool ApplySeccomp(const std::vector<std::string>& allowed_syscalls) {
    std::vector<sock_filter> filter;
    
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(offsetof(struct seccomp_data, arch))));
#ifdef __x86_64__
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
#else
    return false;
#endif
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(offsetof(struct seccomp_data, nr))));

    // Critical ones
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_execve, 0, 1));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_exit_group, 0, 1));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_exit, 0, 1));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    for (const auto& name : allowed_syscalls) {
        int nr = GetSyscallNr(name);
        if (nr != -1) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nr, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    }

    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    struct sock_fprog prog;
    prog.len = (unsigned short)filter.size();
    prog.filter = filter.data();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
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

    std::string tmp_policy = "/tmp/extracted_policy.bin";
    std::string cmd = "objcopy --dump-section .sacre_policy=" + tmp_policy + " " + target_path + " /dev/null 2>&1";
    std::system(cmd.c_str());

    sacre::policy::Policy policy;
    std::ifstream policy_file(tmp_policy, std::ios::binary);
    if (policy_file.is_open()) {
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(policy_file)),
                                     std::istreambuf_iterator<char>());
        auto result = sacre::policy::Deserialize(buffer.data(), buffer.size());
        if (result.success) {
            policy = std::move(result.value);
        }
        policy_file.close();
        unlink(tmp_policy.c_str());
    }

    int flags = 0;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kPid)) flags |= CLONE_NEWPID;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kNet)) flags |= CLONE_NEWNET;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kMount)) flags |= CLONE_NEWNS;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kIpc)) flags |= CLONE_NEWIPC;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUts)) flags |= CLONE_NEWUTS;
    if (policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUser)) flags |= CLONE_NEWUSER;

    if (flags != 0) {
        unshare(flags);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        if (!policy.allowed_syscalls.empty()) {
            if (!ApplySeccomp(policy.allowed_syscalls)) {
                return 1;
            }
        }

        std::vector<char*> exec_args;
        for (int i = 1; i < argc; ++i) {
            exec_args.push_back(argv[i]);
        }
        exec_args.push_back(nullptr);

        execv(target_path.c_str(), exec_args.data());
        return 1;
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            std::cerr << "Child killed by signal: " << WTERMSIG(status) << std::endl;
            return 128 + WTERMSIG(status);
        }
        return WEXITSTATUS(status);
    }
}
