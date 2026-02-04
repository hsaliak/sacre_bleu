#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "src/common/policy.h"

namespace {

bool SafeExecute(const std::vector<std::string>& args) {
    pid_t const pid = fork();
    if (pid == 0) {
        std::vector<char*> c_args;
        c_args.reserve(args.size() + 1);
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(1);
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return false;
}

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
#ifdef __NR_uname
        {"uname", __NR_uname},
#endif
#ifdef __NR_readlink
        {"readlink", __NR_readlink},
#endif
#ifdef __NR_gettid
        {"gettid", __NR_gettid},
#endif
#ifdef __NR_getpgrp
        {"getpgrp", __NR_getpgrp},
#endif
#ifdef __NR_execveat
        {"execveat", __NR_execveat},
#endif
    };
    auto const iter = syscalls.find(name);
    if (iter != syscalls.end()) return iter->second;
    return -1;
}

bool ApplySeccomp(const std::vector<std::string>& allowed_syscalls) {
    std::vector<sock_filter> filter;
    
    // NOLINTBEGIN(misc-include-cleaner)
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(offsetof(struct seccomp_data, arch))));
#ifdef __x86_64__
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
#else
    return false;
#endif
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(offsetof(struct seccomp_data, nr))));

    // Critical ones
    static constexpr std::array critical_syscalls = {
        SYS_execve, SYS_exit_group, SYS_exit, SYS_brk, SYS_arch_prctl,
        SYS_mmap, SYS_munmap, SYS_mprotect, SYS_fstat, SYS_read, SYS_write,
        SYS_close, SYS_rt_sigaction, SYS_rt_sigprocmask, 
#ifdef __NR_execveat
        __NR_execveat,
#endif
    };

    for (int const syscall_nr : critical_syscalls) {
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(syscall_nr), 0, 1));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    for (const auto& name : allowed_syscalls) {
        int const syscall_nr = GetSyscallNr(name);
        if (syscall_nr != -1) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(syscall_nr), 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    }

    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    struct sock_fprog prog{};
    prog.len = static_cast<unsigned short>(filter.size()); // NOLINT(google-runtime-int)
    prog.filter = filter.data();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        return false;
    }
    // NOLINTEND(misc-include-cleaner)
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_binary> [args...]\n";
        return 1;
    }

    std::string const target_path = argv[1];

    constexpr size_t kPathSize = 34;
    std::array<char, kPathSize> tmp_policy = {"/tmp/sacre_policy_extractedXXXXXX"};
    // NOLINTNEXTLINE(misc-include-cleaner)
    int const tmp_fd = mkstemp(tmp_policy.data());
    if (tmp_fd != -1) {
        close(tmp_fd);
        SafeExecute({"objcopy", "--dump-section", 
                     ".sacre_policy=" + std::string(tmp_policy.data()), 
                     target_path, "/dev/null"});
    }

    sacre::policy::Policy policy;
    {
        std::ifstream policy_file(tmp_policy.data(), std::ios::binary);
        if (policy_file.is_open()) {
            std::vector<uint8_t> const buffer((std::istreambuf_iterator<char>(policy_file)),
                                         std::istreambuf_iterator<char>());
            auto result = sacre::policy::Deserialize(buffer.data(), buffer.size());
            if (result.success) {
                policy = std::move(result.value);
            }
            policy_file.close();
        }
    }
    if (tmp_fd != -1) {
        unlink(tmp_policy.data());
    }

    int flags = 0;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kPid)) != 0U) flags |= CLONE_NEWPID;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kNet)) != 0U) flags |= CLONE_NEWNET;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kMount)) != 0U) flags |= CLONE_NEWNS;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kIpc)) != 0U) flags |= CLONE_NEWIPC;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUts)) != 0U) flags |= CLONE_NEWUTS;
    if ((policy.namespaces & static_cast<uint32_t>(sacre::policy::NamespaceType::kUser)) != 0U) flags |= CLONE_NEWUSER;

    if (flags != 0) {
        unshare(flags);
    }

    pid_t const pid = fork();
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
        exec_args.reserve(static_cast<size_t>(argc));
        for (int i = 1; i < argc; ++i) {
            exec_args.push_back(argv[i]);
        }
        exec_args.push_back(nullptr);

        execv(target_path.c_str(), exec_args.data());
        return 1;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        constexpr int kSignalExitOffset = 128;
        std::cerr << "Child killed by signal: " << WTERMSIG(status) << "\n";
        return kSignalExitOffset + WTERMSIG(status);
    }
    return WEXITSTATUS(status);
}
