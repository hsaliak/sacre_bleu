#include "src/injector/injector.h"
#include "src/common/policy.h"
#include "src/common/raii.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>

static bool safe_execute(char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(1);
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return false;
}

static sacre_status_t read_file(const char *path, char **out_buf, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return SACRE_ERR_IO;
    autoclose int fd_guard = fd;

    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) return SACRE_ERR_IO;
    (void)lseek(fd, 0, SEEK_SET);

    *out_buf = (char*)malloc((size_t)size + 1);
    if (!*out_buf) return SACRE_ERR_MALLOC;

    if (read(fd, (void*)*out_buf, (size_t)size) != (ssize_t)size) {
        free((void*)*out_buf);
        *out_buf = NULL;
        return SACRE_ERR_IO;
    }
    (*out_buf)[size] = '\0';
    if (out_size) *out_size = (size_t)size;
    return SACRE_OK;
}

static sacre_status_t run_injection(const sacre_inject_args_t *args) {
    autofree char *ini_content = NULL;
    sacre_status_t status = read_file(args->policy_path, &ini_content, NULL);
    if (status != SACRE_OK) return status;
    
    autopolicy sacre_policy_t policy = {0};
    status = sacre_policy_parse_ini(ini_content, &policy);
    if (status != SACRE_OK) return status;
    
    autofree uint8_t *buffer = NULL;
    size_t size = 0;
    status = sacre_policy_serialize(&policy, &buffer, &size);
    if (status != SACRE_OK) return status;
    
    char blob_template[] = "/tmp/sb_blobXXXXXX";
    int fd = mkstemp(blob_template);
    if (fd < 0) return SACRE_ERR_IO;
    autoclose int fd_guard = fd;
    autounlink char *blob_path = strdup(blob_template);
    
    if (write(fd, buffer, size) != (ssize_t)size) {
        return SACRE_ERR_IO;
    }
    close(fd); fd_guard = -1; 
    
    char *const remove_argv[] = {(char*)"objcopy", (char*)"--remove-section=.sandbox", (char*)args->source_path, (char*)args->target_path, NULL};
    (void)safe_execute(remove_argv);

    char add_arg[512];
    (void)snprintf(add_arg, sizeof(add_arg), ".sandbox=%s", blob_path);
    char *const add_argv[] = {(char*)"objcopy", (char*)"--add-section", add_arg, (char*)args->target_path, NULL};
    bool success = safe_execute(add_argv);
    
    return success ? SACRE_OK : SACRE_ERR_INTERNAL;
}

static sacre_status_t run_extraction(const sacre_inject_args_t *args) {
    char dump_template[] = "/tmp/sb_dumpXXXXXX";
    int fd = mkstemp(dump_template);
    if (fd < 0) return SACRE_ERR_IO;
    autoclose int fd_guard = fd;
    autounlink char *dump_path = strdup(dump_template);
    close(fd); fd_guard = -1;
    
    char dump_arg[512];
    (void)snprintf(dump_arg, sizeof(dump_arg), ".sandbox=%s", dump_path);
    char *const dump_argv[] = {(char*)"objcopy", (char*)"--dump-section", dump_arg, (char*)args->elf_path, NULL};
    if (!safe_execute(dump_argv)) {
        return SACRE_ERR_INTERNAL;
    }
    
    autofree uint8_t *buffer = NULL;
    size_t size = 0;
    sacre_status_t status = read_file(dump_path, (char**)&buffer, &size);
    if (status != SACRE_OK) return status;
    
    autopolicy sacre_policy_t policy = {0};
    status = sacre_policy_deserialize(buffer, size, &policy);
    if (status != SACRE_OK) return status;
    
    autofclose FILE *out_guard = NULL;
    FILE *out = stdout;
    if (args->output_path) {
        out_guard = fopen(args->output_path, "w");
        if (!out_guard) return SACRE_ERR_IO;
        out = out_guard;
    }
    
    (void)fprintf(out, "[seccomp]\nallow = ");
    for (size_t i = 0; i < policy.allowed_syscalls_count; ++i) {
        (void)fprintf(out, "%s%s", policy.allowed_syscalls[i], (i == policy.allowed_syscalls_count - 1 ? "" : ", "));
    }
    (void)fprintf(out, "\n\n[landlock]\nro = ");
    for (size_t i = 0; i < policy.ro_paths_count; ++i) {
        (void)fprintf(out, "%s%s", policy.ro_paths[i], (i == policy.ro_paths_count - 1 ? "" : ", "));
    }
    (void)fprintf(out, "\nrw = ");
    for (size_t i = 0; i < policy.rw_paths_count; ++i) {
        (void)fprintf(out, "%s%s", policy.rw_paths[i], (i == policy.rw_paths_count - 1 ? "" : ", "));
    }
    (void)fprintf(out, "\n");
    
    return SACRE_OK;
}

sacre_status_t sacre_inject_run(const sacre_inject_args_t *args) {
    if (args->is_extraction) return run_extraction(args);
    return run_injection(args);
}
