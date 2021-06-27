#ifndef CLIENT_H
#define CLIENT_H

#include "main.h"

bool parse_args(int argc, char **argv);

void print_usage();

void print_help();

int client(int argc, char **argv);

#endif