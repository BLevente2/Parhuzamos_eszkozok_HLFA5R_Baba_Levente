#ifndef HASH_STORE_H
#define HASH_STORE_H

#include <stddef.h>

typedef struct {
    char     *path;
    char      hex_digest[65];
} HashRecord;

typedef struct {
    HashRecord *records;
    size_t      count;
} HashStore;

int        hs_write(const char *out_filepath, const HashStore *store);
HashStore *hs_read(const char *in_filepath);
void       hs_free(HashStore *store);

#endif
