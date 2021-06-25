
#include "gen.h"

#ifndef IP_H
#define IP_H

#define IP_MAX_COUNT 256  ////
#define IP_NAME_SIZE 16   ////

#define ip_pattern "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."\
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."\
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."\
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$"

// struct iface_s;

struct ip_s {
    struct iface_s *parent;
    int size;
    char ip_str[IP_NAME_SIZE];
    int data_count;
} typedef ip_t;

ip_t construct_ip(char *ip_str, int data_count);

int ipcmp (const void *ip1, const void *ip2);

void print_ip_stat(ip_t *ip);

#endif
