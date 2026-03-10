#include <stdlib.h>
#include "thread_manager.h"

Assignment *tm_assign(const FileList *fl, size_t thread_count) {
    Assignment *a = malloc(sizeof *a);
    a->thread_count = thread_count;
    a->start_idx = malloc(thread_count * sizeof *a->start_idx);
    a->end_idx   = malloc(thread_count * sizeof *a->end_idx);
    uint64_t total = fl->total_size;
    uint64_t target = total / thread_count;
    size_t idx = 0;
    uint64_t cumulative = 0;
    for (size_t t = 0; t < thread_count; ++t) {
        a->start_idx[t] = idx;
        if (t == thread_count - 1) {
            a->end_idx[t] = fl->count;
            break;
        }
        uint64_t limit = target * (t + 1);
        while (idx < fl->count && cumulative < limit) {
            cumulative += fl->entries[idx].size;
            idx++;
        }
        a->end_idx[t] = idx;
    }
    return a;
}

void tm_free(Assignment *a) {
    free(a->start_idx);
    free(a->end_idx);
    free(a);
}
