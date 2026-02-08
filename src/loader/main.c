#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <elf.h>
#include <seccomp.h>
#include <linux/landlock.h>

#include "src/common/policy.h"
#include "src/common/raii.h"

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

static inline int sys_landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
    return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static inline int sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags) {
    return (int)syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline int sys_landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    return (int)syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static sacre_status_t find_sandbox_section(const char *path, uint8_t **out_buffer, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return SACRE_ERR_IO;
    autoclose int fd_guard = fd;

    struct stat st = {0};
    if (fstat(fd, &st) < 0) return SACRE_ERR_IO;

    sacre_map_t map = {0};
    map.len = (size_t)st.st_size;
    map.addr = mmap(NULL, map.len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map.addr == MAP_FAILED) return SACRE_ERR_IO;
    automunmap sacre_map_t map_guard = map;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)map.addr;
    if (memcmp(ehdr->e_ident, ELFMAG, (size_t)SELFMAG) != 0) return SACRE_ERR_PARSE;

    const Elf64_Shdr *shdr = (const Elf64_Shdr *)((const uint8_t *)map.addr + ehdr->e_shoff);
    const char *shstrtab = (const char *)((const uint8_t *)map.addr + shdr[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < (int)ehdr->e_shnum; i++) {
        if (strcmp(shstrtab + shdr[i].sh_name, ".sandbox") == 0) {
            *out_size = (size_t)shdr[i].sh_size;
            *out_buffer = (uint8_t*)malloc(*out_size);
            if (!*out_buffer) return SACRE_ERR_MALLOC;
            memcpy((void*)*out_buffer, (const void*)((const uint8_t *)map.addr + shdr[i].sh_offset), *out_size);
            return SACRE_OK;
        }
    }

    return SACRE_ERR_NOT_FOUND;
}

static bool landlock_add_path(int ruleset_fd, const char *path, uint64_t allowed_access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        // Skip paths that don't exist
        return true;
    }
    autoclose int fd_guard = fd;

    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            allowed_access &= ~LANDLOCK_ACCESS_FS_READ_DIR;
            allowed_access &= ~LANDLOCK_ACCESS_FS_MAKE_DIR;
            allowed_access &= ~LANDLOCK_ACCESS_FS_REMOVE_DIR;
        }
    }

    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = allowed_access,
        .parent_fd = fd,
    };
    if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0) {
        perror("landlock_add_rule");
        return false;
    }
    return true;
}

static bool apply_landlock(char **ro_paths, size_t ro_count, char **rw_paths, size_t rw_count, const char *target_path) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_EXECUTE,
    };

    int ruleset_fd = sys_landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return false;
    }
    autoclose int ruleset_guard = ruleset_fd;

    for (size_t i = 0; i < ro_count; ++i) {
        if (!landlock_add_path(ruleset_fd, ro_paths[i], LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE)) return false;
    }
    for (size_t i = 0; i < rw_count; ++i) {
        if (!landlock_add_path(ruleset_fd, rw_paths[i], attr.handled_access_fs)) return false;
    }
    // Always allow target path for execution
    if (!landlock_add_path(ruleset_fd, target_path, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE)) return false;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl no_new_privs");
        return false;
    }
    if (sys_landlock_restrict_self(ruleset_fd, 0) < 0) {
        perror("landlock_restrict_self");
        return false;
    }
    return true;
}

static bool apply_seccomp(char **allowed_syscalls, size_t count) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) return false;

    size_t crit_count = 0;
    const char **crit_syscalls = sacre_policy_get_critical_syscalls(&crit_count);
    for (size_t i = 0; i < crit_count; ++i) {
        (void)seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(crit_syscalls[i]), 0);
    }

    for (size_t i = 0; i < count; ++i) {
        (void)seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(allowed_syscalls[i]), 0);
    }

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc == 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        fprintf(stderr, "Usage: %s <target_binary> [args...]\n", argv[0]);
        return (argc < 2) ? 1 : 0;
    }

    const char *target_path = argv[1];
    autopolicy sacre_policy_t policy = {0};
    
    autofree uint8_t *buffer = NULL;
    size_t size = 0;
    sacre_status_t status = find_sandbox_section(target_path, &buffer, &size);
    if (status == SACRE_OK) {
        status = sacre_policy_deserialize(buffer, size, &policy);
        if (status != SACRE_OK) {
            fprintf(stderr, "Warning: Failed to deserialize policy from .sandbox section\n");
        }
    } else if (status == SACRE_ERR_NOT_FOUND) {
        fprintf(stderr, "Warning: No .sandbox section found in %s\n", target_path);
    } else {
        fprintf(stderr, "Warning: Error while looking for .sandbox section: %d\n", (int)status);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        if (!apply_landlock(policy.ro_paths, policy.ro_paths_count, policy.rw_paths, policy.rw_paths_count, target_path)) {
            _exit(1);
        }

        if (policy.allowed_syscalls_count > 0) {
            if (!apply_seccomp(policy.allowed_syscalls, policy.allowed_syscalls_count)) {
                _exit(1);
            }
        }

        char **exec_args = (char**)malloc(sizeof(char*) * (size_t)argc);
        if (!exec_args) _exit(1);
        for (int i = 1; i < argc; ++i) {
            exec_args[i - 1] = argv[i];
        }
        exec_args[argc - 1] = NULL;

        (void)execv(target_path, exec_args); // NOLINT(readability-function-cognitive-complexity)
        perror("execv");
        _exit(1);
    }

    int wait_status = 0;
    (void)waitpid(pid, &wait_status, 0);
    if (WIFSIGNALED(wait_status)) {
        fprintf(stderr, "Child killed by signal: %d\n", WTERMSIG(wait_status));
        return 128 + WTERMSIG(wait_status);
    }
    return WEXITSTATUS(wait_status);
}
