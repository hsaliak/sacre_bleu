#ifndef SACRE_COMMON_RAII_H_
#define SACRE_COMMON_RAII_H_

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

/**
 * RAII-style cleanup for pointers allocated via malloc.
 */
static inline void sacre_autofree(void *p) {
    void **ptr = (void **)p;
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

/**
 * RAII-style cleanup for file descriptors.
 */
static inline void sacre_autoclose(int *fd) {
    if (fd && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/**
 * Helper struct and cleanup for mmap'd regions.
 */
typedef struct {
    void *addr;
    size_t len;
} sacre_map_t;

static inline void sacre_automunmap(sacre_map_t *map) {
    if (map && map->addr && map->addr != MAP_FAILED) {
        munmap(map->addr, map->len);
        map->addr = MAP_FAILED;
        map->len = 0;
    }
}

#define autofree __attribute__((cleanup(sacre_autofree)))
#define autoclose __attribute__((cleanup(sacre_autoclose)))
#define automunmap __attribute__((cleanup(sacre_automunmap)))

/**
 * RAII-style cleanup for temporary files.
 */
static inline void sacre_autounlink(char **path) {
    if (path && *path) {
        unlink(*path);
        free(*path);
        *path = NULL;
    }
}

static inline void sacre_autofclose(FILE **f) {
    if (f && *f) {
        fclose(*f);
        *f = NULL;
    }
}

#define autounlink __attribute__((cleanup(sacre_autounlink)))
#define autofclose __attribute__((cleanup(sacre_autofclose)))

#endif // SACRE_COMMON_RAII_H_
