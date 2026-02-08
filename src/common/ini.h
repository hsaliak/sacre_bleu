/* inih -- simple .INI file parser

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/

#ifndef SACRE_COMMON_INI_H_
#define SACRE_COMMON_INI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* Typedef for prototype of handler function. */
typedef int (*ini_handler)(void* user, const char* section_name,
                           const char* entry_name, const char* entry_value); // NOLINT(bugprone-easily-swappable-parameters)

/* Parse given INI-style file. For each entry, call handler function with
   given user pointer, section name, entry name, and entry value. */
int ini_parse(const char* filename, ini_handler handler, void* user);

/* Same as ini_parse(), but takes a FILE* instead of filename. */
int ini_parse_file(FILE* file, ini_handler handler, void* user);

/* Same as ini_parse(), but takes an INI-style string instead of filename. */
int ini_parse_string(const char* string, ini_handler handler, void* user);

/* Nonzero to allow multi-line entries. default is 0. */
#ifndef INI_ALLOW_MULTILINE
#define INI_ALLOW_MULTILINE 1
#endif

/* Nonzero to allow a UTF-8 BOM. default is 1. */
#ifndef INI_ALLOW_BOM
#define INI_ALLOW_BOM 1
#endif

/* Nonzero to allow inline comments. default is 0. */
#ifndef INI_ALLOW_INLINE_COMMENTS
#define INI_ALLOW_INLINE_COMMENTS 1
#endif
#ifndef INI_INLINE_COMMENT_PREFIXES
#define INI_INLINE_COMMENT_PREFIXES ";#"
#endif

/* Nonzero to use stack for line buffer, zero to use heap (malloc/free). */
#ifndef INI_USE_STACK
#define INI_USE_STACK 1
#endif

/* Maximum line length for any line in INI file. */
#ifndef INI_MAX_LINE
#define INI_MAX_LINE 200
#endif

#ifdef __cplusplus
}
#endif

#endif /* SACRE_COMMON_INI_H_ */
