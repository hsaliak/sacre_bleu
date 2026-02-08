#include "src/injector/injector.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Injection: %s <policy.ini> <source_binary> <target_binary>\n", prog);
    fprintf(stderr, "  Extraction: %s --extract <elf_path> [output_path]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help       Show this help message\n");
    fprintf(stderr, "  -e, --extract    Extract policy from an ELF file\n");
}

int main(int argc, char **argv) {
    sacre_inject_args_t args = {0};
    int opt = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"extract", no_argument, 0, 'e'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "he", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'e':
                args.is_extraction = true;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (args.is_extraction) {
        if (optind >= argc) {
            fprintf(stderr, "Error: Missing ELF path for extraction\n");
            print_usage(argv[0]);
            return 1;
        }
        args.elf_path = argv[optind++];
        if (optind < argc) {
            args.output_path = argv[optind++];
        }
    } else {
        if (argc - optind < 3) {
            print_usage(argv[0]);
            return 1;
        }
        args.policy_path = argv[optind++];
        args.source_path = argv[optind++];
        args.target_path = argv[optind++];
    }

    sacre_status_t status = sacre_inject_run(&args);
    if (status != SACRE_OK) {
        fprintf(stderr, "Error: sacre_inject_run failed with status %d\n", (int)status);
        return 1;
    }

    if (args.is_extraction) {
        if (args.output_path) {
            printf("Successfully extracted policy to %s\n", args.output_path);
        }
    } else {
        printf("Successfully injected policy into %s\n", args.target_path);
    }

    return 0;
}
