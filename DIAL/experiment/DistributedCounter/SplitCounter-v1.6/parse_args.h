#ifndef SPLIT_COUTNER_PARSE_ARGS_H_
#define SPLIT_COUTNER_PARSE_ARGS_H_

#include "common.h"

void print_usage();
int parse_args(IN int argc, IN char **argv, OUT const char **pcap_file, OUT const char **topo_file);

#endif // SPLIT_COUTNER_PARSE_ARGS_H_