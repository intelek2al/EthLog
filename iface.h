#ifndef IFACE_H
#define IFACE_H

#include "ip.h"

#define IFACE_MAX_COUNT 64
#define IFACE_NAME_SIZE 128

struct ethlog_s;

struct iface_s {
    struct ethlog_s *parent;
    int ip_count;
    char iface_str[IFACE_NAME_SIZE];
    ip_t *ip[IP_MAX_COUNT];
} typedef iface_t;


iface_t construct_iface(char *iface_str, int ip_count, ip_t *ip, struct ethlog_s *parent);

iface_t copy_iface(iface_t *src_iface);

void push_ip(iface_t *iface, ip_t ip);

int search_ip(ip_t *arr, int l, int r, char *ip_str);

void print_iface_stat(iface_t *iface);

#endif
