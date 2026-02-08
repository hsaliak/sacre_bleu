#ifndef SACRE_COMMON_RESULT_H_
#define SACRE_COMMON_RESULT_H_

// C version of the status codes.
typedef enum {
    SACRE_OK = 0,
    SACRE_ERR_MALLOC,
    SACRE_ERR_PARSE,
    SACRE_ERR_IO,
    SACRE_ERR_INVALID_ARGS,
    SACRE_ERR_NOT_FOUND,
    SACRE_ERR_INTERNAL,
} sacre_status_t;

#endif // SACRE_COMMON_RESULT_H_
