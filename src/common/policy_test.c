#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "src/common/policy.h"
#include "src/common/raii.h"

void test_ini_parsing(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing INI parsing...\n");
    const char *ini = "[seccomp]\nallow = read, write, exit\n\n[landlock]\nro = /usr, /lib\nrw = /tmp";
    autopolicy sacre_policy_t policy = {0};
    sacre_status_t status = sacre_policy_parse_ini(ini, &policy);
    assert(status == SACRE_OK);
    
    assert(policy.allowed_syscalls_count == 3);
    assert(strcmp(policy.allowed_syscalls[0], "read") == 0);
    assert(strcmp(policy.allowed_syscalls[1], "write") == 0);
    assert(strcmp(policy.allowed_syscalls[2], "exit") == 0);
    
    assert(policy.ro_paths_count == 2);
    assert(strcmp(policy.ro_paths[0], "/usr") == 0);
    assert(strcmp(policy.ro_paths[1], "/lib") == 0);
    
    assert(policy.rw_paths_count == 1);
    assert(strcmp(policy.rw_paths[0], "/tmp") == 0);
    
    printf("INI parsing test passed.\n");
}

void test_serialization_roundtrip(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing serialization roundtrip...\n");
    autopolicy sacre_policy_t policy = {0};
    policy.allowed_syscalls_count = 2;
    policy.allowed_syscalls = (char**)malloc(sizeof(char*) * 2);
    policy.allowed_syscalls[0] = strdup("read");
    policy.allowed_syscalls[1] = strdup("write");
    
    policy.ro_paths_count = 1;
    policy.ro_paths = (char**)malloc(sizeof(char*));
    policy.ro_paths[0] = strdup("/etc");
    
    autofree uint8_t *buffer = NULL;
    size_t size = 0;
    sacre_status_t status = sacre_policy_serialize(&policy, &buffer, &size);
    assert(status == SACRE_OK);
    assert(buffer != NULL);
    assert(size > 0);
    
    autopolicy sacre_policy_t restored = {0};
    status = sacre_policy_deserialize(buffer, size, &restored);
    assert(status == SACRE_OK);
    
    assert(restored.allowed_syscalls_count == 2);
    assert(strcmp(restored.allowed_syscalls[0], "read") == 0);
    assert(strcmp(restored.allowed_syscalls[1], "write") == 0);
    assert(restored.ro_paths_count == 1);
    assert(strcmp(restored.ro_paths[0], "/etc") == 0);
    assert(restored.rw_paths_count == 0);
    
    printf("Serialization roundtrip test passed.\n");
}

void test_raii_cleanup(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing RAII cleanup (manual check with ASan)...\n");
    {
        autopolicy sacre_policy_t policy = {0};
        policy.allowed_syscalls_count = 1;
        policy.allowed_syscalls = (char**)malloc(sizeof(char*));
        policy.allowed_syscalls[0] = strdup("test");
        // No manual free here, relies on cleanup attribute
    }
    printf("RAII cleanup test completed.\n");
}

void test_policy_merge(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing policy merge...\n");
    autopolicy sacre_policy_t p1 = {0};
    sacre_policy_add_syscall(&p1, "read");
    sacre_policy_add_ro_path(&p1, "/usr");

    autopolicy sacre_policy_t p2 = {0};
    sacre_policy_add_syscall(&p2, "write");
    sacre_policy_add_syscall(&p2, "read"); // duplicate
    sacre_policy_add_rw_path(&p2, "/tmp");

    sacre_status_t status = sacre_policy_merge(&p1, &p2);
    assert(status == SACRE_OK);

    assert(p1.allowed_syscalls_count == 2);
    assert(p1.ro_paths_count == 1);
    assert(p1.rw_paths_count == 1);

    printf("Policy merge test passed.\n");
}

void test_policy_write_ini(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing policy write INI...\n");
    autopolicy sacre_policy_t p = {0};
    sacre_policy_add_syscall(&p, "read");
    sacre_policy_add_ro_path(&p, "/etc");

    char temp_path[] = "/tmp/sacre_test_XXXXXX";
    int fd = mkstemp(temp_path);
    assert(fd != -1);
    autofclose FILE *f = fdopen(fd, "w+");
    assert(f != NULL);

    sacre_status_t status = sacre_policy_write_ini(f, &p);
    assert(status == SACRE_OK);

    (void)fseek(f, 0, SEEK_SET);
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;

    assert(strstr(buf, "[seccomp]") != NULL);
    assert(strstr(buf, "allow = read") != NULL);
    assert(strstr(buf, "[landlock]") != NULL);
    assert(strstr(buf, "ro = /etc") != NULL);

    unlink(temp_path);
    printf("Policy write INI test passed.\n");
}

int main(void) {
    test_ini_parsing();
    test_serialization_roundtrip();
    test_raii_cleanup();
    test_policy_merge();
    test_policy_write_ini();
    printf("All policy tests passed.\n");
    return 0;
}
