#include "parse_args.h"
#include <string.h>
#include <stdio.h>
#include "common.h"

void print_usage() {
    fprintf(stderr, "Usage: ./<main_program> -p <pcap_filename> -t <topo_filename>\ntopofile format: node_number, edge_number then source destination pair for each edge\n");
    fprintf(stderr, "Easiest usage: make run\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **pcap_file, OUT const char **topo_file) {
//    fprintf(stdout, "argc: %d\n", argc);
	if (argc <= 1) {
            fprintf(stderr, "Too few arguments.\n");
            print_usage();
            return 1;
	}
    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        if (!strcmp(arg, "-p") && i + 1 < argc)	{
            *pcap_file = argv[++i];
        }
		else if (!strcmp(arg, "-t") && i + 1 < argc) {
			*topo_file = argv[++i];
        }
		else {
            fprintf(stderr, "Unknown option '%s'.\n", arg);
            print_usage();
            return 1;
        }
    }
    return 0;
}
