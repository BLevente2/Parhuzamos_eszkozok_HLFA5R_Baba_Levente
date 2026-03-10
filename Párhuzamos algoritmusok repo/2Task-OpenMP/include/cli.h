#ifndef CLI_H
#define CLI_H

#include <stddef.h>

typedef enum {
    MODE_CREATE,
    MODE_CHECK
} Mode;

typedef struct {
    Mode mode;
    const char *input_file;
    const char *hash_file;
    const char *output_file;
    size_t block_size;
    int num_threads;
} ProgramOptions;

int parse_cli(int argc, char *argv[], ProgramOptions *opts);
void print_usage(const char *prog_name);

#endif
