#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <seccomp.h>

#include <algorithm>
#include "src/common/policy.h"
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
/**
 * ARCHITECTURAL OVERVIEW: PTRACE SYSCALL MONITORING
 * ================================================
 * Supervisor-Worker pattern using the Linux ptrace(2) 
 * interface to intercept and log system calls across a process tree.
 *
 * 1. SYNCHRONIZATION HANDSHAKE (Initial Boot)
 * - Child: Calls PTRACE_TRACEME to flag itself for monitoring.
 * - Child: Calls raise(SIGSTOP) to pause and hand control to the Parent.
 * - Parent: Calls waitpid() to synchronize. Once the Child is stopped, the
 * Parent configures PTRACE_O_TRACESYSGOOD. This ensures that syscall 
 * traps are reported as (SIGTRAP | 0x80), allowing the Parent to 
 * distinguish between a system call and a standard signal (like SIGINT).
 *
 * 2. THE EVENT LOOP (State Machine)
 * The Parent runs a loop (waitpid) responding to three Child states:
 *
 * A. SYSCALL TRAPS (SIGTRAP | 0x80):
 * The kernel stops the child twice for every syscall:
 * - Entry: Before the syscall executes (arguments are readable).
 * - Exit: After the syscall executes (return value is readable).
 * Action: Parent logs the syscall and restarts the child via PTRACE_SYSCALL.
 *
 * B. PTRACE EVENTS (status >> 16 != 0):
 * Occurs when the child clones, forks, or execs (via PTRACE_O_TRACE* flags).
 * Action: Parent extracts the new PID (if forking) using PTRACE_GETEVENTMSG,
 * adds it to the monitoring set, and kickstarts the NEW child.
 *
 * C. SIGNAL PASS-THROUGH (The "Else" Logic):
 * Occurs when the child receives a standard signal or hits the post-exec trap.
 * Management signals (SIGSTOP, SIGTRAP) used by ptrace 
 * must be consumed (delivered as 0) by the Parent. If re-injected, the 
 * Child enters a "Signal Loop" hang, where it stops immediately upon restart.
 *
 * 3. MULTI-PROCESS MANAGEMENT
 * By using PTRACE_O_TRACEFORK, the kernel automatically attaches the Parent 
 * to any children spawned by the initial process. The Parent must manage 
 * a set of active PIDs and only exit when the entire process tree has terminated.
 *
 * 4. THE EXECV BOUNDARY
 * When execv() is called, the address space is wiped and a new binary is loaded.
 * The kernel sends a final "kick" SIGTRAP to the child immediately after 
 * the new image starts. The Parent catches this and continues with signal 0 
 * to allow the target program to begin execution.
 */

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

  std::cout << "exec target\n";
  execv(target_path.c_str(), exec_args.data());
  perror("execv");
  _exit(1);
}

void HandlePtraceStop(pid_t pid, int status, std::set<pid_t>& active_pids, std::set<std::string>& syscalls) { // NOLINT
  int const sig = WSTOPSIG(status);

  // Handle new threads/processes
  if (sig == SIGTRAP && (status >> 16) != 0) {
    pid_t new_pid = 0;
    if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid) == 0) {
      active_pids.insert(new_pid);
      // Kick the new PID 
      ptrace(PTRACE_SYSCALL, new_pid, nullptr, nullptr);
    }
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    return;
  }

  if (sig == (SIGTRAP | 0x80)) {
    int64_t const nr = GetSyscallNr(pid);
    if (nr >= 0) {
      syscalls.insert(GetSyscallName(static_cast<int>(nr)));
    }
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
  } else {
    // Forward other signals
    // If it's SIGSTOP (from the raise) or SIGTRAP (from the exec), 
    // pass 0 to consume the signal so the child can actually proceed.
    int const signal_to_deliver = (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig;
    ptrace(PTRACE_SYSCALL, pid, nullptr, reinterpret_cast<void*>(static_cast<intptr_t>(signal_to_deliver))); // NOLINT
  }
}

std::set<std::string> TraceProcess(pid_t pid) {
  int status = 0;
  waitpid(pid, &status, 0); // Wait for SIGSTOP

  uint64_t const options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                           PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
  if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, options) != 0) {
    perror("ptrace(PTRACE_SETOPTIONS)");
    return {};
  }

  std::set<std::string> syscalls;
  std::set<pid_t> active_pids;
  active_pids.insert(pid);
  // Kick trace before while loop
  ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

  while (!active_pids.empty()) {
    pid_t const current_pid = waitpid(-1, &status, 0);
    if (current_pid < 0) {
      if (errno == ECHILD) break;
      perror("waitpid");
      break;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      active_pids.erase(current_pid);
      continue;
    }

    if (WIFSTOPPED(status)) {
      HandlePtraceStop(current_pid, status, active_pids, syscalls);
    }
  }
  return syscalls;
}

void WritePolicy(const std::string& path, const std::string& target_path, const std::set<std::string>& syscalls) {
  std::ofstream out(path);
  if (!out.is_open()) {
    std::cerr << "Failed to open output file: " << path << "\n";
    return;
  }

  out << "[landlock]\n";
  out << "# Suggested read-only paths for basic execution\n";
  out << "ro = /usr/lib, /lib64, /etc/ld.so.cache, /lib/x86_64-linux-gnu, " << target_path << "\n";
  out << "# rw = /tmp\n\n";

  out << "[seccomp]\n";
  out << "# The following critical syscalls are ALWAYS allowed by the loader and cannot be overridden.\n";
  out << "# They are defined in sacre::policy::GetCriticalSyscalls().\n";
  out << "\n";
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
    std::cout << "running target\n";
    RunChild(target_path, argc, argv);
  }

  auto syscalls = TraceProcess(pid);

  // Remove critical syscalls that are always allowed by the loader
  for (const auto& critical : sacre::policy::GetCriticalSyscalls()) {
    syscalls.erase(critical);
  }

  WritePolicy(output_path, target_path, syscalls);

  std::cout << "Generated policy with " << syscalls.size() << " syscalls to " << output_path << "\n";

  return 0;
}
