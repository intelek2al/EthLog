#include "ehtlog.h"
#include "iface.h"

ethlog_t construct_ethlog() {
    ethlog_t ethlog;
    char errbuf[100];

    ethlog.iface_count = 0;
    ethlog.ip_count = 0;
    ethlog.iface_current = -1;
    ethlog.is_active = false;

    if(pcap_findalldevs( &ethlog.alldevsp, errbuf)) {
        printf("construct_ethlog: %s\n", errbuf);
		return ethlog;
    }

    for (pcap_if_t *dev = ethlog.alldevsp; dev; dev = dev->next) {
        iface_t iface = construct_iface(dev->name, 0, dev->description, NULL, &ethlog);
        push_iface(&ethlog, iface);
    }
    ethlog.handler = pcap_open_live(ethlog.iface[ethlog.iface_current].iface_str, 65536, 1, 1, errbuf);
    if(ethlog.handler == NULL) {
        printf("construct_ethlog: %s\n", errbuf);
		return ethlog;
    }
    
    return ethlog;
}

int ifacecmp(const void *if1, const void *if2) {
    return strcmp(((const iface_t *)if1)->iface_str, ((const iface_t *)if2)->iface_str);
}

iface_t *push_iface(ethlog_t *ethlog, iface_t iface) {
    if (ethlog->iface_count + 1 > IFACE_MAX_COUNT) {
        fprintf(stderr, "IFace buffer overflow\n");
        exit(1);
    }
    int exist_idx = search_iface(ethlog->iface, 0, ethlog->iface_count - 1, iface.iface_str);
    if (exist_idx != -1) {
        return &ethlog->iface[exist_idx];
    } 
    iface.parent = ethlog;
    ethlog->iface[++ethlog->iface_count - 1] = iface;
    if (ethlog->iface_count != 0 && ethlog->iface_current == -1)
        ethlog->iface_current = 0;
    // qsort(ethlog->iface, ethlog->iface_count, sizeof(iface_t), ifacecmp);
    return &ethlog->iface[ethlog->iface_count - 1];
}

void find_print_ip(ethlog_t *ethlog, char *ip_str) {
    int ip_idx = search_ip(ethlog->ip, 0, ethlog->ip_count - 1, ip_str);
    if (ip_idx != -1) {
        for (int i = 0; ip_idx + i < IFACE_MAX_COUNT * IP_MAX_COUNT && ip_idx - i >= 0; i++) {// going to different side ( ...<-ip0<-|ip1|->ip2->... ) from found ip
            int flag = 0;
            if (strcmp(ethlog->ip[ip_idx + i].ip_str, ip_str) == 0) {
                printf("Interface \"%s\":\n", ethlog->ip[ip_idx + i].parent->iface_str);
                print_ip_stat(&ethlog->ip[ip_idx + i]);
                flag++;
            }
            if (strcmp(ethlog->ip[ip_idx - i].ip_str, ip_str) == 0 && i != 0) {
                printf("Interface \"%s\":\n", ethlog->ip[ip_idx - i].parent->iface_str);
                print_ip_stat(&ethlog->ip[ip_idx - i]);
                flag++;
            }
            write(0, "\n", 1);
            if (flag == 0)
                break;
        }
    }
    else {
        printf("IP does not exist!\n");
    }
}

int search_iface(iface_t *arr, int l, int r, char *iface_str) {
    if (r >= l) {
        int mid = l + (r - l) / 2;
        // printf("|%s|, |%s|\n", arr[mid].iface_str, iface_str);
        if (strcmp(arr[mid].iface_str, iface_str) == 0)
            return mid;
        if (strcmp(arr[mid].iface_str, iface_str) > 0)
            return search_iface(arr, l, mid - 1, iface_str);
  
        return search_iface(arr, mid + 1, r, iface_str);
    }
    return -1;
}

void find_print_iface(ethlog_t *ethlog, char *iface_str) {
    int iface_idx = search_iface(ethlog->iface, 0, ethlog->iface_count - 1, iface_str);
    if (iface_idx != -1) {
        print_iface_stat(&ethlog->iface[iface_idx]);
    }
    else {
        printf("Interface does not exist!\n");
    }
}

void serializer(ethlog_t *ethlog) {
    FILE *fd = fopen("/var/run/ethlog.dat", "wb");

    if (!fd) {
        perror("ethlog");
        fprintf(stderr, "Try with sudo\n");
        exit(EXIT_FAILURE);
    }

    char buff[sizeof(sz_connector_t) + sizeof(ethlog_t)];
    
    sz_connector_t connector = tosz(ethlog);
    // for (int i = 0; i < connector.iface_count; i++)
    //     for (int j = 0; j < connector.iface[i].ip_count; j++) {
    //         printf("iface %d: ip %d\n", i, connector.iface[i].ip[j]);
    //     }
    

    memcpy(buff, &connector, sizeof(sz_connector_t));
    memcpy((buff + sizeof(sz_connector_t)), ethlog, sizeof(ethlog_t));

    if (fwrite(buff, sizeof(sz_connector_t) + sizeof(ethlog_t), 1, fd) != 1) {
        perror("ethlog");
        exit(EXIT_FAILURE);
    }
    fclose(fd);
}

ethlog_t *deserializer(ethlog_t *ethlog) {
    FILE *fd = fopen("/var/run/ethlog.dat", "rb");
    if (!fd) {
        perror("ethlog");
        *ethlog = construct_ethlog();
        return ethlog;
    }

    char buff[sizeof(sz_connector_t) + sizeof(ethlog_t)];
    sz_connector_t connector;

    int ret = fread(buff, sizeof(sz_connector_t) + sizeof(ethlog_t), 1, fd);
    if (ret != 1) {
        *ethlog = construct_ethlog();
    }
    else {
        memcpy(&connector, buff, sizeof(sz_connector_t));
        memcpy(ethlog, (buff + sizeof(sz_connector_t)), sizeof(ethlog_t));
        fromsz(ethlog, &connector);
    }
    // for (int i = 0; i < connector.iface_count; i++)
    //     for (int j = 0; j < connector.iface[i].ip_count; j++) {
    //         printf("iface %d: ip %d\n", i, connector.iface[i].ip[j]);
    //     }
    fclose(fd);
    return ethlog;
}

sz_connector_t tosz(ethlog_t *ethlog) { // normal to serializable
    sz_connector_t connector;

    connector.iface_count = ethlog->iface_count;
    for (int i_ifc = 0; i_ifc < ethlog->iface_count; i_ifc++) {
        connector.iface[i_ifc].ip_count = ethlog->iface[i_ifc].ip_count;
        for (int i_ip = 0; i_ip < ethlog->iface[i_ifc].ip_count; i_ip++) {
            connector.iface[i_ifc].ip[i_ip] = ethlog->iface[i_ifc].ip[i_ip] - &ethlog->ip[0]; // finding index in global ip array
        }
    }
    return connector;
}

void fromsz(ethlog_t *ethlog, sz_connector_t *connector) {
    for (int i_ifc = 0; i_ifc < connector->iface_count; i_ifc++) {
        for (int i_ip = 0; i_ip < connector->iface[i_ifc].ip_count; i_ip++) {
            ip_t *ip = &ethlog->ip[connector->iface[i_ifc].ip[i_ip]];
            ip->parent = &ethlog->iface[i_ifc];
            ethlog->iface[i_ifc].ip[i_ip] = ip;
        }
        ethlog->iface[i_ifc].parent = ethlog;
    }
}

