#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

#include <stddef.h>
#include "file_scanner.h"

typedef struct {
    size_t *start_idx;
    size_t *end_idx;
    size_t  thread_count;
} Assignment;

Assignment *tm_assign(const FileList *fl, size_t thread_count);
void        tm_free(Assignment *a);

#endif
