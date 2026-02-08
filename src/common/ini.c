#include "src/common/ini.h"
#include "src/common/raii.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static char* trim(char* s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

int ini_parse_string(const char* string, ini_handler handler, void* user) {
    autofree char* line = strdup(string);
    if (!line) return -1;

    autofree char* section = strdup("");
    char* saveptr = NULL;
    char* current_line = strtok_r(line, "\n", &saveptr);

    while (current_line) {
        char* l = trim(current_line);
        if (*l == '\0' || *l == '#' || *l == ';') goto next;

        if (*l == '[' && l[strlen(l) - 1] == ']') {
            char* next_section = strdup(l + 1);
            if (next_section) {
                free(section);
                section = next_section;
                section[strlen(section) - 1] = '\0';
            }
        } else {
            char* eq = strchr(l, '=');
            if (eq) {
                *eq = '\0';
                char* key = trim(l);
                char* value = trim(eq + 1);
                if (!handler(user, section, key, value)) {
                    return -2;
                }
            }
        }

    next:
        current_line = strtok_r(NULL, "\n", &saveptr);
    }

    return 0;
}
