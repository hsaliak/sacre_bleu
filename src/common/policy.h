#ifndef SACRE_COMMON_POLICY_H_
#define SACRE_COMMON_POLICY_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "src/common/raii.h"
#include "src/common/result.h"

typedef struct {
    char **allowed_syscalls;
    size_t allowed_syscalls_count;
    char **ro_paths;
    size_t ro_paths_count;
    char **rw_paths;
    size_t rw_paths_count;
} sacre_policy_t;

/**
 * Frees all memory associated with a policy.
 */
void sacre_policy_free(sacre_policy_t *policy);

/**
 * RAII cleanup handler for policy.
 */
static inline void sacre_autopolicy(sacre_policy_t *policy) {
    sacre_policy_free(policy);
}

#define autopolicy __attribute__((cleanup(sacre_autopolicy)))

/**
 * Parses an INI string into a Policy object.
 */
sacre_status_t sacre_policy_parse_ini(const char *ini_content, sacre_policy_t *out_policy);

/**
 * Serializes a Policy object into a binary blob.
 * Returns SACRE_OK on success. The caller must free *out_buffer.
 */
sacre_status_t sacre_policy_serialize(const sacre_policy_t *policy, uint8_t **out_buffer, size_t *out_size);

/**
 * Deserializes a binary blob into a Policy object.
 */
sacre_status_t sacre_policy_deserialize(const uint8_t *buffer, size_t size, sacre_policy_t *out_policy);

/**
 * Returns a static list of critical syscalls.
 * The strings are NOT owned by the caller.
 */
const char** sacre_policy_get_critical_syscalls(size_t *out_count);

#endif // SACRE_COMMON_POLICY_H_
