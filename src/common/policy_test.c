#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "src/common/policy.h"

void test_ini_parsing(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing INI parsing...\n");
    const char *ini = "[seccomp]\nallow = read, write, exit\n\n[landlock]\nro = /usr, /lib\nrw = /tmp";
    sacre_policy_t policy;
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
    
    sacre_policy_free(&policy);
    printf("INI parsing test passed.\n");
}

void test_serialization_roundtrip(void) { // NOLINT(readability-function-cognitive-complexity)
    printf("Testing serialization roundtrip...\n");
    sacre_policy_t policy = {0};
    policy.allowed_syscalls_count = 2;
    policy.allowed_syscalls = (char**)malloc(sizeof(char*) * 2);
    policy.allowed_syscalls[0] = strdup("read");
    policy.allowed_syscalls[1] = strdup("write");
    
    policy.ro_paths_count = 1;
    policy.ro_paths = (char**)malloc(sizeof(char*));
    policy.ro_paths[0] = strdup("/etc");
    
    uint8_t *buffer = NULL;
    size_t size = 0;
    sacre_status_t status = sacre_policy_serialize(&policy, &buffer, &size);
    assert(status == SACRE_OK);
    assert(buffer != NULL);
    assert(size > 0);
    
    sacre_policy_t restored = {0};
    status = sacre_policy_deserialize(buffer, size, &restored);
    assert(status == SACRE_OK);
    
    assert(restored.allowed_syscalls_count == 2);
    assert(strcmp(restored.allowed_syscalls[0], "read") == 0);
    assert(strcmp(restored.allowed_syscalls[1], "write") == 0);
    assert(restored.ro_paths_count == 1);
    assert(strcmp(restored.ro_paths[0], "/etc") == 0);
    assert(restored.rw_paths_count == 0);
    
    sacre_policy_free(&policy);
    sacre_policy_free(&restored);
    free(buffer);
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

int main(void) {
    test_ini_parsing();
    test_serialization_roundtrip();
    test_raii_cleanup();
    printf("All policy tests passed.\n");
    return 0;
}
