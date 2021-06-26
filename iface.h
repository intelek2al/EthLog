#ifndef IFACE_H
#define IFACE_H

#include "ip.h"

#define IFACE_MAX_COUNT 64
#define IFACE_NAME_SIZE 128
#define IFACE_DSCR_SIZE 128

struct ethlog_s;

struct iface_s {
    struct ethlog_s *parent;
    int ip_count;
    char description[IFACE_DSCR_SIZE];
    char iface_str[IFACE_NAME_SIZE];
    ip_t *ip[IP_MAX_COUNT];
} typedef iface_t;

struct sz_iface_s {
    int ip_count;
    int ip[IP_MAX_COUNT]; // indexes in ethlog_t ip array
} typedef sz_iface_t;

iface_t construct_iface(char *iface_str, int ip_count, char *dscr, ip_t *ip, struct ethlog_s *parent);

iface_t copy_iface(iface_t *src_iface);

void push_ip(iface_t *iface, ip_t ip);

int search_ip(ip_t *arr, int l, int r, char *ip_str);

int search_ip_iface(ip_t *arr, int l, int r, char *ip_str, char *iface);

void print_iface_stat(iface_t *iface);

#endif
