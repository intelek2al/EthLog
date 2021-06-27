#include "daemon.h"
#include "ehtlog.h"

extern int socket_fd;
extern bool isdaemon;
extern bool run;

static void handler(int sig) {
    run = false;
}

void signal_action_handler() {
    struct sigaction sigact;
    sigact.sa_handler = &handler;
    sigemptyset(&sigact.sa_mask);
    if (sigaction(SIGINT, &sigact, NULL) != 0 || sigaction(SIGQUIT, &sigact, NULL) != 0 || sigaction(SIGTERM, &sigact, NULL) != 0) {
        fprintf(stderr, "ehtlog: Could not set up signal handlers!\n");
        cleanup();
        exit(EXIT_FAILURE);
    }
}

void process(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer) {
    ethlog_t *ethlog = (ethlog_t *)user;
    iface_t *current_iface = &ethlog->iface[ethlog->iface_current];

    if (ethlog->is_active == false) {
        return;
    }

	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
    char *ip_str = inet_ntoa(source.sin_addr);

    int find_idx = search_ip_iface(current_iface, 0, current_iface->ip_count - 1, ip_str);

    if (find_idx == -1) {
        ip_t ip = construct_ip(ip_str, 1);
        push_ip(current_iface, ip);
    } else {
        ethlog->ip[find_idx].data_count++;
    }

}

void *sniff_callback(void *data) {
    ethlog_t *ethlog = (ethlog_t *)data;
    printf("Start sniffing on selected interface: %s\n", ethlog->iface[ethlog->iface_current].iface_str);
    pcap_loop(ethlog->handler, -1, process, (u_char *)ethlog);
    return NULL;
}


int daemon_server() {
    ethlog_t ethlog;
    construct_ethlog(&ethlog);

    struct msghdr msg = {0};
    struct iovec iovec;
    message_t client_message;
    iovec.iov_base = &client_message;
    iovec.iov_len = sizeof(client_message);
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;

    thread_pack_t sniff_thread;
    pthread_attr_init(&sniff_thread.attr);
    pthread_mutex_init(&sniff_thread.mtx, NULL);

    deserializer(&ethlog);

    while (run) {
        int ret = recvmsg(socket_fd, &msg, MSG_DONTWAIT);
        if (ret != sizeof(client_message)) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("ehtlog: Error while accessing socket");
                exit(1);
            }
        } else {
            request_handler(&ethlog, client_message, &sniff_thread);
        }
    }
    serializer(&ethlog);
    printf("ehtlog: Daemon ethlog is terminated!\n");
    pthread_mutex_destroy(&sniff_thread.mtx);
    pthread_cancel(sniff_thread.trd);
    pthread_join(sniff_thread.trd, NULL);
    pcap_close(ethlog.handler);
    serializer(&ethlog);
    cleanup();
    return EXIT_FAILURE;
}

int show_count(ethlog_t *ethlog, char *ip) {
    find_print_ip(ethlog, ip);
    return 0;
}

void *sniff_callback(void *data);
void stop_sniff(ethlog_t *ethlog, thread_pack_t *thread);
void start_sniff(ethlog_t *ethlog, thread_pack_t *thread);

int select_iface(ethlog_t *ethlog, char *eth, thread_pack_t *thread) {
    stop_sniff(ethlog, thread);
    char errbuf[100];

    int new_ifc = search_iface(ethlog->iface, ethlog->iface_count, eth);
    if (new_ifc == -1) {
        fprintf(stderr, "ethlog: Interface does not exist!\n");
        return 1;
    }

    ethlog->iface_current = new_ifc;
    pcap_close(ethlog->handler);
    ethlog->handler = pcap_open_live(ethlog->iface[ethlog->iface_current].iface_str, 65536, 1, 0, errbuf);
    if (ethlog->handler == NULL) 
	{
		fprintf(stderr, "ethlog: Couldn't open device %s : %s\n" , eth , errbuf);
		return 1;
	}
    if (ethlog->is_active)
        start_sniff(ethlog, thread);

    return 0;
}

int stat_iface(ethlog_t *ethlog, char *iface, bool is_all) {
    if (is_all) {
        for (int i = 0; i < ethlog->iface_count; i++)
            print_iface_stat(&ethlog->iface[i]);
    }
    else
        find_print_iface(ethlog, iface);
    return 0;
}

void print_all_iface(ethlog_t *ethlog) {
    if (ethlog->iface_count == 0) {
        printf("ethlog: All interfaces are inavailable.");
        return;
    }
    printf("Available interfaces:\n");
    for (int i = 0; i < ethlog->iface_count; i++) {
        printf("%d. %s", i + 1, ethlog->iface[i].iface_str);
        if (ethlog->iface[i].description[0] != '\0')
            printf(" (%s)", ethlog->iface[i].description);
        printf("\n");
    }
    
}

void start_sniff(ethlog_t *ethlog, thread_pack_t *thread) {
    pthread_mutex_lock(&thread->mtx);
    ethlog->is_active = true;
    pthread_mutex_unlock(&thread->mtx);
    pthread_create(&thread->trd, &thread->attr, sniff_callback, ethlog);
}

void stop_sniff(ethlog_t *ethlog, thread_pack_t *thread) {
    pthread_mutex_lock(&thread->mtx);
    ethlog->is_active = false;
    pthread_mutex_unlock(&thread->mtx);
    pthread_cancel(thread->trd);
    pthread_join(thread->trd, NULL);
}

int clear(ethlog_t *ethlog, thread_pack_t *thread) {
    stop_sniff(ethlog, thread);
    if (remove("/var/run/ethlog.dat") != 0)
        printf("ethlog: Failed clearing!\n");
    ethlog_t ethlog_new;
    construct_ethlog(&ethlog_new);
    memmove(ethlog, &ethlog_new, sizeof(ethlog_t));
    return 0;
}

void request_handler(ethlog_t *ethlog, message_t message, thread_pack_t *thread) {
    switch (message.flag) {   
        case FLAG_START:
            start_sniff(ethlog, thread);
            break;
        case FLAG_STOP:
            stop_sniff(ethlog, thread);
            break;
        case FLAG_SHOW:
            show_count(ethlog, message.buf);
            break;
        case FLAG_SELECT:
            select_iface(ethlog, message.buf, thread);
            break;
        case FLAG_STAT:
            stat_iface(ethlog, message.buf, false);
            break;
        case FLAG_STAT_ALL:
            stat_iface(ethlog, message.buf, true);
            break;
        case FLAG_CLEAR:
            clear(ethlog, thread);
            break;
        case FLAG_IFACES:
            print_all_iface(ethlog);
            break;
        case FLAG_EXIT:
            run = false;
            break;
    }
}
