#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/landlock.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <csignal>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <seccomp.h>
#include <cstring>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "src/common/policy.h"
#include "src/common/file_closer.h"

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
    return seccomp_syscall_resolve_name(name.c_str());
}

bool ApplyLandlock(const std::vector<std::string>& ro_paths, const std::vector<std::string>& rw_paths, const std::string& target_path) {
    if (ro_paths.empty() && rw_paths.empty()) {
        return true;
    }

    uint64_t const abi1_flags =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM;

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

    int const abi = static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION));
    uint64_t handled_flags = abi1_flags;
    if (abi >= 2) {
        // LANDLOCK_ACCESS_FS_REFER is special: it allows linking and renaming files
        // between different directories. Enabling it is safer as it prevents bypasses
        // that might occur if we only allowed basic read/write but not referral.
        handled_flags |= LANDLOCK_ACCESS_FS_REFER;
    }

    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = handled_flags;

    int const ruleset_fd = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0));
    if (ruleset_fd < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP) {
            std::cerr << "Landlock not supported by the kernel, skipping.\n";
            return true;
        }
        perror("landlock_create_ruleset");
        return false;
    }

    auto add_path_rule = [&](const std::string& path, uint64_t allowed_access) {
        int const fd = open(path.c_str(), O_PATH | O_CLOEXEC);
        if (fd < 0) {
            std::cerr << "Warning: could not open path '" << path << "' for Landlock (" << path << "), skipping.\n";
            return true;
        }

        struct stat st{};
        if (fstat(fd, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                allowed_access &= ~LANDLOCK_ACCESS_FS_READ_DIR;
                // Some flags might only be for directories?
                // Actually, according to Landlock docs, most flags are fine for files if they make sense.
            }
        }

        struct landlock_path_beneath_attr path_attr = {};
        path_attr.allowed_access = allowed_access;
        path_attr.parent_fd = fd;

        if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0) {
            std::cerr << "landlock_add_rule failed for " << path << ": " << strerror(errno) << "\n";
            close(fd);
            return false;
        }
        close(fd);
        return true;
    };

    uint64_t const ro_flags = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;

    // Always allow the target binary itself
    add_path_rule(target_path, ro_flags);

    for (const auto& path : ro_paths) {
        if (!add_path_rule(path, ro_flags)) return false;
    }

    for (const auto& path : rw_paths) {
        if (!add_path_rule(path, handled_flags)) return false;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        close(ruleset_fd);
        return false;
    }

    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return false;
    }

    close(ruleset_fd);
    return true;
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
    for (const auto& name : sacre::policy::GetCriticalSyscalls()) {
        int const syscall_nr = GetSyscallNr(name);
        if (syscall_nr >= 0) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(syscall_nr), 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    }

    for (const auto& name : allowed_syscalls) {
        int const syscall_nr = GetSyscallNr(name);
        if (syscall_nr != -1) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(syscall_nr), 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        } else {
            std::cerr << "Warning: unknown syscall '" << name << "' in policy, ignoring.\n";
        }
    }

    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

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

    constexpr size_t kPathSize = 35;
    std::array<char, kPathSize> tmp_policy = {"/tmp/sacre_policy_extractedXXXXXX"};
    {
        sacre::FileCloser const tmp_fd(mkstemp(tmp_policy.data()));
        if (tmp_fd.is_valid()) {
            if (!SafeExecute({"objcopy", "--dump-section", 
                             ".sandbox=" + std::string(tmp_policy.data()), 
                             target_path, "/dev/null"})) {
                std::cerr << "Warning: Failed to extract .sandbox section from " << target_path << "\n";
            }
        }
    }

    sacre::policy::Policy policy;
    {
        std::ifstream policy_file(tmp_policy.data(), std::ios::binary);
        if (policy_file.is_open()) {
            std::vector<uint8_t> const buffer((std::istreambuf_iterator<char>(policy_file)),
                                         std::istreambuf_iterator<char>());
            if (buffer.empty()) {
                std::cerr << "Warning: Extracted policy buffer is empty\n";
            }
            auto result = sacre::policy::Deserialize(buffer.data(), buffer.size());
            if (result.success) {
                policy = std::move(result.value);
            } else {
                std::cerr << "Error: Failed to deserialize policy: " << result.error_message << "\n";
            }
            policy_file.close();
        } else {
             // This is expected if the binary has no .sandbox section and no policy was passed on CLI
             if (argc == 2) {
                 std::cerr << "Warning: No .sandbox section found in " << target_path << " and no policy file provided\n";
             }
        }
    }
    unlink(tmp_policy.data());



    pid_t const pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        if (!ApplyLandlock(policy.ro_paths, policy.rw_paths, target_path)) {
            _exit(1);
        }

        if (!policy.allowed_syscalls.empty()) {
            if (!ApplySeccomp(policy.allowed_syscalls)) {
                _exit(1);
            }
        }

        std::vector<char*> exec_args;
        exec_args.reserve(static_cast<size_t>(argc));
        for (int i = 1; i < argc; ++i) {
            exec_args.push_back(argv[i]);
        }
        exec_args.push_back(nullptr);

        execv(target_path.c_str(), exec_args.data());
        perror("execv");
        _exit(1);
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
