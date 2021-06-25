#ifndef ETHLOG_H
#define ETHLOG_H


#define IFACE_MAX_COUNT 64  ///
#define IFACE_NAME_SIZE 128 ///

#include "iface.h"

struct ethlog_s {
    int iface_count;
    int iface_current;
    int ip_count;
    iface_t iface[IFACE_MAX_COUNT];
    ip_t ip[IFACE_MAX_COUNT * IP_MAX_COUNT];
} typedef ethlog_t;

ethlog_t construct_ethlog();

iface_t *push_iface(ethlog_t *ethlog, iface_t iface);

void find_print_ip(ethlog_t *ethlog, char *ip_str);

#endif
