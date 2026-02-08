#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <seccomp.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>

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

static inline void sacre_autosysset(syscall_set_t *set) {
    syscall_set_free(set);
}

#define autosysset __attribute__((cleanup(sacre_autosysset)))

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

    char *exec_args[argc - 1];
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
            autofree char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr);
            if (name) {
                syscall_set_add(syscalls, name);
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
    autopolicy sacre_policy_t policy = {0};
    
    // Default RO paths
    (void)sacre_policy_add_ro_path(&policy, "/usr/lib");
    (void)sacre_policy_add_ro_path(&policy, "/lib64");
    (void)sacre_policy_add_ro_path(&policy, "/etc/ld.so.cache");
    (void)sacre_policy_add_ro_path(&policy, "/lib/x86_64-linux-gnu");
    (void)sacre_policy_add_ro_path(&policy, target_path);

    for (size_t i = 0; i < syscalls->count; ++i) {
        (void)sacre_policy_add_syscall(&policy, syscalls->names[i]);
    }

    autofclose FILE *out = fopen(path, "w");
    if (!out) {
        perror("fopen");
        return;
    }

    (void)sacre_policy_write_ini(out, &policy);
}

static int do_merge(int argc, char **argv) {
    const char *output_path = NULL;
    int opt = 0;
    // We need to reset optind if we use getopt multiple times, but here it's fine as it's the first time.
    while ((opt = getopt(argc, argv, "o:")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            default:
                return 1;
        }
    }

    if (!output_path || optind >= argc) {
        fprintf(stderr, "Usage: %s merge -o <output_ini> <input1.ini> <input2.ini> ...\n", argv[0]);
        return 1;
    }

    autopolicy sacre_policy_t master_policy = {0};
    for (int i = optind; i < argc; ++i) {
        autofclose FILE *f = fopen(argv[i], "r");
        if (!f) {
            fprintf(stderr, "Failed to open input: %s\n", argv[i]);
            perror("fopen");
            return 1;
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        autofree char *content = malloc((size_t)fsize + 1);
        if (!content) return 1;
        if (fread(content, 1, (size_t)fsize, f) != (size_t)fsize) return 1;
        content[fsize] = 0;
        
        autopolicy sacre_policy_t p = {0};
        if (sacre_policy_parse_ini(content, &p) != SACRE_OK) {
            fprintf(stderr, "Failed to parse %s\n", argv[i]);
            return 1;
        }
        
        if (sacre_policy_merge(&master_policy, &p) != SACRE_OK) {
            fprintf(stderr, "Failed to merge %s\n", argv[i]);
            return 1;
        }
    }

    autofclose FILE *out = fopen(output_path, "w");
    if (!out) {
        perror("fopen");
        return 1;
    }
    if (sacre_policy_write_ini(out, &master_policy) != SACRE_OK) {
        fprintf(stderr, "Failed to write merged policy\n");
        return 1;
    }

    printf("Successfully merged %d policies into %s\n", argc - optind, output_path);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <output_ini> <target_binary> [args...]\n", argv[0]);
        fprintf(stderr, "       %s merge -o <output_ini> <input1.ini> <input2.ini> ...\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "merge") == 0) {
        return do_merge(argc - 1, argv + 1);
    }

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

    autosysset syscall_set_t syscalls = {0};
    if (pid == 0) {
        run_child(target_path, argc, argv);
    } else {
        trace_process(pid, &syscalls);
        write_policy(output_path, target_path, &syscalls);
        printf("Generated policy with %zu syscalls to %s\n", syscalls.count, output_path);
    }

    return 0;
}
