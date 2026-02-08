#include "src/common/policy.h"
#include "src/common/ini.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static bool list_contains(char **list, size_t count, const char *item) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(list[i], item) == 0) return true;
    }
    return false;
}

static sacre_status_t append_unique(char ***list, size_t *count, const char *item) {
    if (list_contains(*list, *count, item)) return SACRE_OK;
    char **new_list = (char**)realloc((void*)*list, sizeof(char*) * (*count + 1));
    if (!new_list) return SACRE_ERR_MALLOC;
    *list = new_list;
    char *new_token = strdup(item);
    if (!new_token) return SACRE_ERR_MALLOC;
    (*list)[*count] = new_token;
    (*count)++;
    return SACRE_OK;
}

enum {
    MAGIC = 0x00524353,
    VERSION = 1,
};

typedef enum {
    TAG_SECCOMP = 2,
    TAG_LANDLOCK_RO = 3,
    TAG_LANDLOCK_RW = 4,
} tag_t;

sacre_status_t sacre_policy_merge(sacre_policy_t *dest, const sacre_policy_t *src) {
    if (!dest || !src) return SACRE_ERR_INVALID_ARGS;
    
    for (size_t i = 0; i < src->allowed_syscalls_count; ++i) {
        sacre_status_t s = append_unique(&dest->allowed_syscalls, &dest->allowed_syscalls_count, src->allowed_syscalls[i]);
        if (s != SACRE_OK) return s;
    }
    for (size_t i = 0; i < src->ro_paths_count; ++i) {
        sacre_status_t s = append_unique(&dest->ro_paths, &dest->ro_paths_count, src->ro_paths[i]);
        if (s != SACRE_OK) return s;
    }
    for (size_t i = 0; i < src->rw_paths_count; ++i) {
        sacre_status_t s = append_unique(&dest->rw_paths, &dest->rw_paths_count, src->rw_paths[i]);
        if (s != SACRE_OK) return s;
    }
    return SACRE_OK;
}

static void write_list_ini(FILE *out, const char *key, char **list, size_t count) {
    if (count == 0) return;
    fprintf(out, "%s = ", key);
    for (size_t i = 0; i < count; ++i) {
        fprintf(out, "%s%s", list[i], (i == count - 1) ? "" : ", ");
    }
    fprintf(out, "\n");
}

sacre_status_t sacre_policy_write_ini(FILE *out, const sacre_policy_t *policy) {
    if (!out || !policy) return SACRE_ERR_INVALID_ARGS;
    
    if (policy->allowed_syscalls_count > 0) {
        fprintf(out, "[seccomp]\n");
        write_list_ini(out, "allow", policy->allowed_syscalls, policy->allowed_syscalls_count);
        fprintf(out, "\n");
    }
    
    if (policy->ro_paths_count > 0 || policy->rw_paths_count > 0) {
        fprintf(out, "[landlock]\n");
        write_list_ini(out, "ro", policy->ro_paths, policy->ro_paths_count);
        write_list_ini(out, "rw", policy->rw_paths, policy->rw_paths_count);
    }
    
    return SACRE_OK;
}

void sacre_policy_free(sacre_policy_t *policy) {
    if (!policy) return;
    for (size_t i = 0; i < policy->allowed_syscalls_count; ++i) free((void*)policy->allowed_syscalls[i]);
    free((void*)policy->allowed_syscalls);
    for (size_t i = 0; i < policy->ro_paths_count; ++i) free((void*)policy->ro_paths[i]);
    free((void*)policy->ro_paths);
    for (size_t i = 0; i < policy->rw_paths_count; ++i) free((void*)policy->rw_paths[i]);
    free((void*)policy->rw_paths);
    memset((void*)policy, 0, sizeof(*policy));
}

static void add_to_list(char*** list, size_t* count, const char* val) {
    if (!val) return;
    autofree char* v = strdup(val);
    char* saveptr = NULL;
    char* token = strtok_r(v, ",", &saveptr);
    while (token) {
        while (isspace((unsigned char)*token)) token++;
        if (*token) {
            char* end = token + strlen(token) - 1;
            while (end > token && isspace((unsigned char)*end)) end--;
            end[1] = '\0';
            if (*token) {
                (void)append_unique(list, count, token);
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
}

static int policy_handler(void* user, const char* section_name, const char* entry_name, const char* entry_value) { // NOLINT(bugprone-easily-swappable-parameters)
    sacre_policy_t* p = (sacre_policy_t*)user;

    if (strcmp(section_name, "seccomp") == 0 && strcmp(entry_name, "allow") == 0) {
        add_to_list(&p->allowed_syscalls, &p->allowed_syscalls_count, entry_value);
    } else if (strcmp(section_name, "landlock") == 0) {
        if (strcmp(entry_name, "ro") == 0) {
            add_to_list(&p->ro_paths, &p->ro_paths_count, entry_value);
        } else if (strcmp(entry_name, "rw") == 0) {
            add_to_list(&p->rw_paths, &p->rw_paths_count, entry_value);
        }
    }
    return 1;
}

sacre_status_t sacre_policy_parse_ini(const char *ini_content, sacre_policy_t *out_policy) {
    if (!ini_content || !out_policy) return SACRE_ERR_INVALID_ARGS;
    memset(out_policy, 0, sizeof(*out_policy));
    if (ini_parse_string(ini_content, policy_handler, out_policy) != 0) {
        sacre_policy_free(out_policy);
        return SACRE_ERR_PARSE;
    }
    return SACRE_OK;
}

static void push_u32(uint8_t **buf, size_t *offset, uint32_t val) {
    memcpy(*buf + *offset, &val, 4);
    *offset += 4;
}

static void push_u16(uint8_t **buf, size_t *offset, uint16_t val) {
    memcpy(*buf + *offset, &val, 2);
    *offset += 2;
}

static size_t list_size(char** list, size_t count) {
    if (count == 0) return 0;
    size_t s = 4 + 4; // Tag(2) + Len(2) + Count(4)
    for (size_t i = 0; i < count; ++i) s += strlen(list[i]) + 1;
    return s;
}

static void push_list(uint8_t **out_buffer, size_t *offset, tag_t tag, char** list, size_t count) {
    if (count == 0) return;
    push_u16(out_buffer, offset, (uint16_t)tag);
    size_t len_offset = *offset;
    *offset += 2; // placeholder for length
    size_t start_offset = *offset;
    
    push_u32(out_buffer, offset, (uint32_t)count);
    for (size_t i = 0; i < count; ++i) {
        size_t slen = strlen(list[i]) + 1;
        memcpy(*out_buffer + *offset, list[i], slen);
        *offset += slen;
    }
    uint16_t total_len = (uint16_t)(*offset - start_offset);
    memcpy(*out_buffer + len_offset, &total_len, 2);
}

sacre_status_t sacre_policy_serialize(const sacre_policy_t *policy, uint8_t **out_buffer, size_t *out_size) {
    if (!policy || !out_buffer || !out_size) return SACRE_ERR_INVALID_ARGS;

    size_t size = 12; // Magic, Version, Entry Count
    uint32_t entry_count = 0;

    size_t s_seccomp = list_size(policy->allowed_syscalls, policy->allowed_syscalls_count);
    size_t s_ro = list_size(policy->ro_paths, policy->ro_paths_count);
    size_t s_rw = list_size(policy->rw_paths, policy->rw_paths_count);

    size += s_seccomp + s_ro + s_rw;
    if (s_seccomp) entry_count++;
    if (s_ro) entry_count++;
    if (s_rw) entry_count++;

    *out_buffer = malloc(size);
    if (!*out_buffer) return SACRE_ERR_MALLOC;
    *out_size = size;

    size_t offset = 0;
    push_u32(out_buffer, &offset, MAGIC);
    push_u32(out_buffer, &offset, VERSION);
    push_u32(out_buffer, &offset, entry_count);

    push_list(out_buffer, &offset, TAG_SECCOMP, policy->allowed_syscalls, policy->allowed_syscalls_count);
    push_list(out_buffer, &offset, TAG_LANDLOCK_RO, policy->ro_paths, policy->ro_paths_count);
    push_list(out_buffer, &offset, TAG_LANDLOCK_RW, policy->rw_paths, policy->rw_paths_count);

    return SACRE_OK;
}

static uint32_t read_u32(const uint8_t *buf, size_t *offset) {
    uint32_t val = 0;
    memcpy(&val, buf + *offset, 4);
    *offset += 4;
    return val;
}

static uint16_t read_u16(const uint8_t *buf, size_t *offset) {
    uint16_t val = 0;
    memcpy(&val, buf + *offset, 2);
    *offset += 2;
    return val;
}

sacre_status_t sacre_policy_deserialize(const uint8_t *buffer, size_t size, sacre_policy_t *out_policy) {
    if (!buffer || !out_policy) return SACRE_ERR_INVALID_ARGS;
    memset(out_policy, 0, sizeof(*out_policy));

    if (size < 12) return SACRE_ERR_PARSE;
    size_t offset = 0;
    if (read_u32(buffer, &offset) != MAGIC) return SACRE_ERR_PARSE;
    if (read_u32(buffer, &offset) != VERSION) return SACRE_ERR_PARSE;
    uint32_t entry_count = read_u32(buffer, &offset);

    for (uint32_t i = 0; i < entry_count; ++i) {
        if (offset + 4 > size) break;
        uint16_t tag = read_u16(buffer, &offset);
        uint16_t len = read_u16(buffer, &offset);
        if (offset + len > size) break;

        size_t entry_start = offset;
        uint32_t count = read_u32(buffer, &offset);
        char*** list = NULL;
        size_t* pcount = NULL;

        if (tag == TAG_SECCOMP) { list = &out_policy->allowed_syscalls; pcount = &out_policy->allowed_syscalls_count; }
        else if (tag == TAG_LANDLOCK_RO) { list = &out_policy->ro_paths; pcount = &out_policy->ro_paths_count; }
        else if (tag == TAG_LANDLOCK_RW) { list = &out_policy->rw_paths; pcount = &out_policy->rw_paths_count; }
        else { offset += len - 4; continue; }

        *list = (char**)calloc(count, sizeof(char*));
        if (!*list) return SACRE_ERR_MALLOC;
        *pcount = count;
        for (uint32_t j = 0; j < count; ++j) {
            const char* s = (const char*)(buffer + offset);
            size_t slen = strlen(s) + 1;
            (*list)[j] = strdup(s);
            offset += slen;
        }
        
        // Ensure we consumed exactly len bytes (including count)
        offset = entry_start + len;
    }

    return SACRE_OK;
}

const char** sacre_policy_get_critical_syscalls(size_t *out_count) {
    static const char* critical_syscalls[] = {
        "execve",          "exit_group",      "exit",
        "brk",             "arch_prctl",      "mmap",
        "munmap",          "mprotect",        "fstat",
        "read",            "write",           "close",
        "rt_sigaction",    "rt_sigprocmask",  "rt_sigreturn",
        "newfstatat",      "openat",          "readlink",
        "getpid",          "gettid",          "set_tid_address",
        "set_robust_list", "futex",           "prlimit64",
        "getrandom",       "rseq",            "prctl",
        "pread64",         "access",          "open",
        "stat",            "lstat",           "fstatfs",
        "getdents64",      "ioctl",           "fcntl",
        "writev",          "getuid",          "getgid",
        "geteuid",         "getegid",         "lseek",
        "dup",             "dup2",            "dup3",
        "pipe",            "pipe2",           "execveat"
    };
    *out_count = sizeof(critical_syscalls) / sizeof(critical_syscalls[0]);
    return critical_syscalls;
}
