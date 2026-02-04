#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <seccomp.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#if defined(__x86_64__)
#define SYSCALL_REG orig_rax
#elif defined(__i386__)
#define SYSCALL_REG orig_eax
#elif defined(__aarch64__)
#define SYSCALL_REG regs[8]
#else
#error "Unsupported architecture"
#endif

namespace {

std::string GetSyscallName(int nr) {
  const char* name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
  if (name != nullptr) {
    return name;
  }
  return "unknown(" + std::to_string(nr) + ")";
}

int64_t GetSyscallNr(pid_t pid) {
  struct user_regs_struct regs{};
  if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != 0) {
    perror("ptrace(PTRACE_GETREGS)");
    return -1;
  }
  return static_cast<int64_t>(regs.SYSCALL_REG);
}

void RunChild(const std::string& target_path, int argc, char** argv) {
  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
    perror("ptrace(PTRACE_TRACEME)");
    _exit(1);
  }
  raise(SIGSTOP);

  std::vector<char*> exec_args;
  exec_args.reserve(static_cast<size_t>(argc) - 1);
  for (int i = 2; i < argc; ++i) {
    exec_args.push_back(argv[i]);
  }
  exec_args.push_back(nullptr);

  execv(target_path.c_str(), exec_args.data());
  perror("execv");
  _exit(1);
}

std::set<std::string> TraceProcess(pid_t pid) {
  int status = 0;
  waitpid(pid, &status, 0); // Wait for SIGSTOP

  if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) != 0) {
    perror("ptrace(PTRACE_SETOPTIONS)");
    return {};
  }

  std::set<std::string> syscalls;
  bool is_entry = true;

  while (true) {
    if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) != 0) {
      if (errno == ESRCH) {
        break; // Child exited
      }
      perror("ptrace(PTRACE_SYSCALL)");
      break;
    }

    waitpid(pid, &status, 0);

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      break;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
      if (is_entry) {
        int64_t const nr = GetSyscallNr(pid);
        if (nr >= 0) {
          syscalls.insert(GetSyscallName(static_cast<int>(nr)));
        }
      }
      is_entry = !is_entry;
    }
  }
  return syscalls;
}

void WritePolicy(const std::string& path, const std::set<std::string>& syscalls) {
  std::ofstream out(path);
  if (!out.is_open()) {
    std::cerr << "Failed to open output file: " << path << "\n";
    return;
  }

  out << "[namespaces]\n";
  out << "user = true\n";
  out << "net = true\n";
  out << "# pid = true\n";
  out << "# mount = true\n";
  out << "# ipc = true\n";
  out << "# uts = true\n\n";

  out << "[seccomp]\n";
  out << "allow = ";
  bool first = true;
  for (const auto& name : syscalls) {
    if (!first) {
      out << ", ";
    }
    out << name;
    first = false;
  }
  out << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <output_ini> <target_binary> [args...]\n";
    return 1;
  }

  std::string const output_path = argv[1];
  std::string const target_path = argv[2];

  pid_t const pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    RunChild(target_path, argc, argv);
  }

  auto const syscalls = TraceProcess(pid);
  WritePolicy(output_path, syscalls);

  std::cout << "Generated policy with " << syscalls.size() << " syscalls to " << output_path << "\n";

  return 0;
}
