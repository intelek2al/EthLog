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
    bool is_active;
    
    pcap_t *handler;
    pcap_if_t *alldevsp;

    // thread_pack_t sniff_thread;
} typedef ethlog_t;

struct sz_connector_s {
    int iface_count;
    sz_iface_t iface[IFACE_MAX_COUNT];
} typedef sz_connector_t;


ethlog_t *construct_ethlog(ethlog_t *);

iface_t *push_iface(ethlog_t *ethlog, iface_t iface);

void find_print_ip(ethlog_t *ethlog, char *ip_str);

// ======= SERIALIZING ==========

void serializer(ethlog_t *ethlog);

ethlog_t *deserializer(ethlog_t *ethlog);

sz_connector_t tosz(ethlog_t *ethlog);

void fromsz(ethlog_t *ethlog, sz_connector_t *connector);

// ======= ============ ==========

int search_iface(iface_t *arr, int size, char *iface_str);

void find_print_iface(ethlog_t *ethlog, char *iface_str);

#endif
