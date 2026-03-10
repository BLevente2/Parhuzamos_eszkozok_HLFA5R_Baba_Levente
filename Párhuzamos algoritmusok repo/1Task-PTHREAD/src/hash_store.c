#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_store.h"

int hs_write(const char *out_filepath, const HashStore *store) {
    FILE *f = fopen(out_filepath, "w");
    if (!f) return -1;
    for (size_t i = 0; i < store->count; ++i) {
        fprintf(f, "%s  %s\n",
                store->records[i].hex_digest,
                store->records[i].path);
    }
    fclose(f);
    return 0;
}

HashStore *hs_read(const char *in_filepath) {
    FILE *f = fopen(in_filepath, "r");
    if (!f) return NULL;

    size_t cap = 16;
    size_t cnt = 0;
    HashRecord *arr = malloc(cap * sizeof *arr);
    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, f) != -1) {
        if (cnt == cap) {
            cap *= 2;
            arr = realloc(arr, cap * sizeof *arr);
        }
        char *hex = strtok(line, " \t");
        char *path = strtok(NULL, "\n");
        arr[cnt].path = strdup(path);
        /* hex_digest egy 65 bájtos buffer, hogy elférjen a 64 hex karakter + '\0' */
        strncpy(arr[cnt].hex_digest, hex, 65);
        cnt++;
    }
    free(line);
    fclose(f);

    HashStore *store = malloc(sizeof *store);
    store->records = arr;
    store->count   = cnt;
    return store;
}

void hs_free(HashStore *store) {
    for (size_t i = 0; i < store->count; ++i) {
        free(store->records[i].path);
    }
    free(store->records);
    /* Ne szabadítsuk fel magát a store pointert,
       mert lehet, hogy a hívó stack-en allokálta azt. */
}
