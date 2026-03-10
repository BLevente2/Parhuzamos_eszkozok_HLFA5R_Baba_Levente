#ifndef FILE_SCANNER_H
#define FILE_SCANNER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     *path;
    uint64_t  size;
} FileEntry;

typedef struct {
    FileEntry *entries;
    size_t     count;
    uint64_t   total_size;
} FileList;

FileList *fs_scan_directory(const char *dir_path);
void      fs_free(FileList *fl);

#endif
