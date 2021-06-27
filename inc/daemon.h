#ifndef DAEMON_H
#define DAEMON_H

#include "main.h"
#include "ehtlog.h"
#include "connect.h"

void signal_action_handler();

void process(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer);

void *sniff_callback(void *data);

int daemon_server();

int show_count(ethlog_t *ethlog, char *ip);

int select_iface(ethlog_t *ethlog, char *eth, thread_pack_t *thread);\

int stat_iface(ethlog_t *ethlog, char *iface, bool is_all);

void print_all_iface(ethlog_t *ethlog);

void start_sniff(ethlog_t *ethlog, thread_pack_t *thread);

void stop_sniff(ethlog_t *ethlog, thread_pack_t *thread);

int clear(ethlog_t *ethlog, thread_pack_t *thread);

void request_handler(ethlog_t *ethlog, message_t message, thread_pack_t *thread);


#endif