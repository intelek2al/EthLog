#include "iface.h"
#include "ehtlog.h"

iface_t construct_iface(char *iface_str, int ip_count, ip_t *ip, ethlog_t *parent) {
    iface_t iface;
    iface.parent = parent;
    iface.ip_count = ip_count;
    if (strlen(iface_str) > IFACE_NAME_SIZE) {
        fprintf(stderr, "IFACE name is overflowed\n");
        exit(1);
    }
    strcpy(iface.iface_str, iface_str);
    memcpy(iface.ip, ip, ip_count);
    return iface;
}

iface_t copy_iface(iface_t *src_iface) {
    iface_t iface;
    iface.parent = src_iface->parent;
    iface.ip_count = src_iface->ip_count;
    strcpy(iface.iface_str, src_iface->iface_str);
    memcpy(iface.ip, src_iface->ip, src_iface->ip_count);
    return iface;
}

void push_ip(iface_t *iface, ip_t ip) {
    ethlog_t *ethlog = iface->parent;

    if (!ethlog)
        return;
    ip.parent = iface;
    ethlog->ip[++(ethlog->ip_count) - 1] = ip;
    iface->ip[++iface->ip_count - 1] = &(ethlog->ip[ethlog->ip_count - 1]);
    qsort(ethlog->ip, iface->ip_count, sizeof(ip_t), ipcmp);
}

int search_ip(ip_t *arr, int l, int r, char *ip_str) {
    if (r >= l) {
        int mid = l + (r - l) / 2;

        if (strcmp(arr[mid].ip_str, ip_str) == 0)
            return mid;
        if (strcmp(arr[mid].ip_str, ip_str) > 0)
            return search_ip(arr, l, mid - 1, ip_str);
  
        return search_ip(arr, mid + 1, r, ip_str);
    }
    return -1;
}

static int count_packet(iface_t *iface) {
    int buf = 0;
    for (int i = 0; i < iface->ip_count; i++) {
        buf += iface->ip[i]->data_count;
    }
    return buf;
}

void print_iface_stat(iface_t *iface) {
    printf("Common info of interface \"%s\":\n\n", iface->iface_str);
    printf("\tCount of IP: \t\t| %d\n", iface->ip_count);
    printf("\tTotal received packets:\t| %d\n\n", count_packet(iface));
    printf("\t----------------------------------\n\n");
    for (int i = 0; i < iface->ip_count; i++) {
        print_ip_stat(iface->ip[i]);
    }
    printf("\n==========================================\n\n");
}
