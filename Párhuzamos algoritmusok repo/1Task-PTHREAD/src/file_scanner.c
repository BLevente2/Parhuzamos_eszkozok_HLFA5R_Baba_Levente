#include "file_scanner.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static int ensure_capacity(FileEntry **entries, size_t *cap, size_t count) {
    if (count < *cap) return 0;
    size_t new_cap = *cap ? *cap * 2 : 16;
    FileEntry *tmp = realloc(*entries, new_cap * sizeof(FileEntry));
    if (!tmp) return -1;
    *entries = tmp;
    *cap = new_cap;
    return 0;
}

static void scan_dir(const char *dir_path,
                     FileEntry **entries, size_t *count, size_t *cap,
                     uint64_t *total_size) {
    DIR *dp = opendir(dir_path);
    if (!dp) return;
    struct dirent *de;
    while ((de = readdir(dp))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        size_t len = strlen(dir_path) + 1 + strlen(de->d_name) + 1;
        char *full = malloc(len);
        strcpy(full, dir_path);
        strcat(full, "/");
        strcat(full, de->d_name);
        struct stat st;
        if (stat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_dir(full, entries, count, cap, total_size);
            } else if (S_ISREG(st.st_mode)) {
                if (ensure_capacity(entries, cap, *count) == 0) {
                    (*entries)[*count].path = full;
                    (*entries)[*count].size = (uint64_t)st.st_size;
                    *total_size += (uint64_t)st.st_size;
                    (*count)++;
                    continue;
                }
                free(full);
            } else {
                free(full);
            }
        } else {
            free(full);
        }
    }
    closedir(dp);
}

FileList *fs_scan_directory(const char *dir_path) {
    FileEntry *entries = NULL;
    size_t cap = 0, count = 0;
    uint64_t total_size = 0;
    scan_dir(dir_path, &entries, &count, &cap, &total_size);
    FileList *fl = malloc(sizeof(FileList));
    fl->entries = entries;
    fl->count = count;
    fl->total_size = total_size;
    return fl;
}

void fs_free(FileList *fl) {
    for (size_t i = 0; i < fl->count; ++i) {
        free(fl->entries[i].path);
    }
    free(fl->entries);
    free(fl);
}
