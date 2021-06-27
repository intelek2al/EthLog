#ifndef GEN_H
#define GEN_H

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bits/sigaction.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <pthread.h>

struct thread_pack_s {
    pthread_t trd;
    pthread_attr_t attr;
    pthread_mutex_t mtx;
} typedef thread_pack_t;


bool check_regex(char *str, char *pattern);


#define SOCKET_NAME "/tmp/ethlog"

#define DATA_ERROR -1
#define FLAG_EXIT 0
#define FLAG_START 1
#define FLAG_STOP 2
#define FLAG_SHOW 3
#define FLAG_SELECT 4
#define FLAG_STAT 5
#define FLAG_STAT_ALL 6
#define FLAG_IFACES 7
#define FLAG_CLEAR 8


#endif
