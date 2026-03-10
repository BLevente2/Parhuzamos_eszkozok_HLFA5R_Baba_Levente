#ifndef APP_H
#define APP_H

#include <stddef.h>

typedef enum {
    MODE_CREATE,
    MODE_CHECK
} AppMode;

int parse_args(int argc, char **argv, AppMode *mode,
               const char **first_path, const char **second_path,
               size_t *thread_count);

int app_create(const char *dir_path, const char *out_hash_file);
int app_check(const char *hash_file, const char *dir_path, size_t thread_count);

#endif
