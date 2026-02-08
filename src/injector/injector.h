#ifndef SACRE_INJECTOR_INJECTOR_H_
#define SACRE_INJECTOR_INJECTOR_H_

#include "src/common/result.h"
#include <stdbool.h>

typedef struct {
    const char *policy_path;
    const char *source_path;
    const char *target_path;
    const char *elf_path;
    const char *output_path;
    bool is_extraction;
} sacre_inject_args_t;

sacre_status_t sacre_inject_run(const sacre_inject_args_t *args);

#endif // SACRE_INJECTOR_INJECTOR_H_
