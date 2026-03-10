#ifndef CHECKER_H
#define CHECKER_H

#include <stddef.h>
#include <stdint.h>
#include "hash_store.h"
#include "file_scanner.h"
#include "thread_manager.h"

size_t checker_serial(const HashStore *hs, const FileList *fl, size_t *error_count);

typedef struct {
    const HashStore   *hs;
    const FileList    *fl;
    const Assignment  *asgn;
    size_t             thread_id;
    size_t            *error_count;
    uint64_t           bytes_processed;
} CheckerArgs;

void *checker_worker(void *arg);

#endif
