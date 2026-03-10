#include "cli.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static const char *MODE_CREATE_STR = "create";
static const char *MODE_CHECK_STR  = "check";

int parse_cli(int argc, char *argv[], ProgramOptions *opts)
{
    if (argc < 2)
        return -1;

    if (strcmp(argv[1], MODE_CREATE_STR) == 0)
        opts->mode = MODE_CREATE;
    else if (strcmp(argv[1], MODE_CHECK_STR) == 0)
        opts->mode = MODE_CHECK;
    else
        return -1;

    opts->input_file  = NULL;
    opts->hash_file   = NULL;
    opts->output_file = NULL;
    opts->block_size  = 0;
    opts->num_threads = 1;

    int c;
    while ((c = getopt(argc - 1, argv + 1, "i:h:o:b:t:")) != -1) {
        switch (c) {
            case 'i':
                opts->input_file = optarg;
                break;
            case 'h':
                opts->hash_file = optarg;
                break;
            case 'o':
                opts->output_file = optarg;
                break;
            case 'b':
                opts->block_size = strtoul(optarg, NULL, 0);
                break;
            case 't':
                opts->num_threads = atoi(optarg);
                break;
            default:
                return -1;
        }
    }

    if (!opts->input_file || !opts->block_size)
        return -1;

    if (opts->mode == MODE_CREATE) {
        if (!opts->output_file)
            return -1;
    } else {
        if (!opts->hash_file || opts->num_threads < 1)
            return -1;
    }

    return 0;
}

void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s create -i INPUT -o OUTPUT -b BLOCK_SIZE [-t THREADS]\n"
        "  %s check  -i INPUT -h HASHFILE -b BLOCK_SIZE -t THREADS\n",
        prog_name, prog_name);
}
