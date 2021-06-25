#include "ip.h"

ip_t construct_ip(char *ip_str, int data_count) {
    ip_t ip;

    if (strlen(ip_str) > IP_NAME_SIZE) {
        fprintf(stderr, "IP name is overflowed\n");
        exit(1);
    }

    if (!check_regex(ip_str, ip_pattern)) {
        fprintf(stderr, "IP name is incorrect\n");
        exit(1);
    }

    strcpy(ip.ip_str, ip_str);
    ip.data_count = data_count;
    return ip;
}

int ipcmp (const void *ip1, const void *ip2) {
    return strcmp(((const ip_t *)ip1)->ip_str, ((const ip_t *)ip2)->ip_str);
}

void print_ip_stat(ip_t *ip) {
    if (ip)
        printf("\tIP \"%s\": %ld packet(s)\n", ip->ip_str, ip->data_count);
}
