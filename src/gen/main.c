#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <seccomp.h>
#include <errno.h>

#include "src/common/policy.h"
#include "src/common/raii.h"

#if defined(__x86_64__)
#define SYSCALL_REG orig_rax
#elif defined(__i386__)
#define SYSCALL_REG orig_eax
#elif defined(__aarch64__)
#define SYSCALL_REG regs[8]
#else
#error "Unsupported architecture"
#endif

typedef struct {
    char **names;
    size_t count;
} syscall_set_t;

static void syscall_set_free(syscall_set_t *set) {
    if (!set) return;
    for (size_t i = 0; i < set->count; ++i) free((void*)set->names[i]);
    free((void*)set->names);
    memset((void*)set, 0, sizeof(*set));
}

static void syscall_set_add(syscall_set_t *set, const char *name) {
    if (!name) return;
    for (size_t i = 0; i < set->count; ++i) {
        if (strcmp(set->names[i], name) == 0) return;
    }
    char** new_names = (char**)realloc((void*)set->names, sizeof(char*) * (set->count + 1));
    if (!new_names) return;
    set->names = new_names;
    set->names[set->count] = strdup(name);
    set->count++;
}

static void run_child(const char *target_path, int argc, char **argv) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_TRACEME)");
        _exit(1);
    }
    (void)raise(SIGSTOP);

    char **exec_args = (char**)malloc(sizeof(char*) * (size_t)argc);
    if (!exec_args) _exit(1);
    for (int i = 2; i < argc; ++i) {
        exec_args[i - 2] = argv[i];
    }
    exec_args[argc - 2] = NULL;

    (void)execv(target_path, exec_args);
    perror("execv");
    _exit(1);
}

static long get_syscall_nr(pid_t pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) return -1;
    return (long)regs.SYSCALL_REG;
}

static void handle_ptrace_stop(pid_t pid, int status, syscall_set_t *syscalls) { // NOLINT(bugprone-easily-swappable-parameters)
    int sig = WSTOPSIG(status);
    if (sig == (SIGTRAP | 0x80)) {
        long nr = get_syscall_nr(pid);
        if (nr >= 0) {
            char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr);
            if (name) {
                syscall_set_add(syscalls, name);
                free(name);
            }
        }
        (void)ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    } else {
        int signal_to_deliver = (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig;
        (void)ptrace(PTRACE_SYSCALL, pid, NULL, (void*)(uintptr_t)signal_to_deliver); // NOLINT(performance-no-int-to-ptr)
    }
}

static void trace_process(pid_t pid, syscall_set_t *syscalls) {
    int status = 0;
    (void)waitpid(pid, &status, 0);

    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                            PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)options) != 0) { // NOLINT(performance-no-int-to-ptr)
        perror("ptrace(PTRACE_SETOPTIONS)");
        return;
    }

    (void)ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

    int active_children = 1;
    while (active_children > 0) {
        pid_t current_pid = waitpid(-1, &status, 0);
        if (current_pid < 0) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            active_children--;
            continue;
        }

        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP && (status >> 16) != 0) {
                // It's a ptrace event (fork, etc)
                (void)ptrace(PTRACE_SYSCALL, current_pid, NULL, NULL);
                if ((status >> 16) == PTRACE_EVENT_FORK || (status >> 16) == PTRACE_EVENT_VFORK || (status >> 16) == PTRACE_EVENT_CLONE) {
                    active_children++;
                }
            } else {
                handle_ptrace_stop(current_pid, status, syscalls);
            }
        }
    }
}

static void write_policy(const char *path, const char *target_path, const syscall_set_t *syscalls) { // NOLINT(bugprone-easily-swappable-parameters)
    FILE *out = fopen(path, "w");
    if (!out) {
        perror("fopen");
        return;
    }

    fprintf(out, "[landlock]\n");
    fprintf(out, "# Suggested read-only paths for basic execution\n");
    fprintf(out, "ro = /usr/lib, /lib64, /etc/ld.so.cache, /lib/x86_64-linux-gnu, %s\n", target_path);
    fprintf(out, "# rw = /tmp\n\n");

    fprintf(out, "[seccomp]\n");
    fprintf(out, "# The following critical syscalls are ALWAYS allowed by the loader and cannot be overridden.\n");
    fprintf(out, "allow = ");

    bool first = true;
    for (size_t i = 0; i < syscalls->count; ++i) {
        if (!first) fprintf(out, ", ");
        fprintf(out, "%s", syscalls->names[i]);
        first = false;
    }
    fprintf(out, "\n");
    fclose(out);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <output_ini> <target_binary> [args...]\n", argv[0]);
        return 1;
    }

    const char *output_path = argv[1];
    const char *target_path = argv[2];

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    syscall_set_t syscalls = {0};
    if (pid == 0) {
        run_child(target_path, argc, argv);
    } else {
        trace_process(pid, &syscalls);
        write_policy(output_path, target_path, &syscalls);
        printf("Generated policy with %zu syscalls to %s\n", syscalls.count, output_path);
        syscall_set_free(&syscalls);
    }

    return 0;
}
