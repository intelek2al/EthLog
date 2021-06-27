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
#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header

#include <pthread.h>

struct thread_pack_s {
    pthread_t trd;
    pthread_attr_t attr;
    pthread_mutex_t mtx;
} typedef thread_pack_t;


bool check_regex(char *str, char *pattern);

#endif
