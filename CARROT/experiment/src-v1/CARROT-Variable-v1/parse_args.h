#ifndef DIAL_PARSE_ARGS_H_
#define DIAL_PARSE_ARGS_H_

#include "common.h"

void print_usage();
int parse_args(IN int argc, IN char **argv, OUT const char **pcap_file, OUT const char **topo_file);

#endif // !DIAL_PARSE_ARGS_H_