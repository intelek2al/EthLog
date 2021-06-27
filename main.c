#include "ehtlog.h"

bool check_regex(char *str, char *pattern) {
    regex_t regex;
    const int n_matches = 3;
    regmatch_t match[n_matches];
    int return_value = 1;
    if (regcomp(&regex, pattern, REG_EXTENDED) == 0) {
        return_value = regexec(&regex, str, n_matches, match, 0);
    }
    regfree(&regex);
    return return_value == 0;
}


struct message_s {
    int fd;
    int flag;
    char buf[64];
} typedef message_t;

static int socket_fd = -1;
static bool isdaemon = false;
static bool run = true;

int singleton_connect(const char *name) {

    int len, tmpd;
    struct sockaddr_un addr = {0};

    if ((tmpd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
        perror("ethlog: Could not create socket\n");
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, name);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

    int ret;
    unsigned int retries = 1;
    do {
        ret = bind(tmpd, (struct sockaddr *)&addr, len);
        if (ret == 0) {
            socket_fd = tmpd;
            isdaemon = true;
            if (fork() != 0 ) {
                return singleton_connect(name);
            }
            umask(0);
            setsid();
            return 0;
        } else {
            if (errno == EADDRINUSE) {
                ret = connect(tmpd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
                if (ret != 0) {
                    if (errno == ECONNREFUSED) {
                        unlink(name);
                        continue;
                    }
                    fprintf(stderr, "ethlog: Could not connect to socket: '%s'.\n", strerror(errno));
                    continue;
                }
                // printf("Daemon is already running.\n");
                socket_fd = tmpd;
                return 1;
            }
            perror("ethlog: Could not bind to socket\n");
            continue;
        }
    } while (retries-- > 0);

    printf("ethlog: Could neither connect to an existing daemon nor become one.\n");
    close(tmpd);
    return -1;
}

static void cleanup(void) {
    if (socket_fd >= 0) {
        if (isdaemon) {
            if (unlink(SOCKET_NAME) < 0)
                printf("Could not remove FIFO.\n");
        } else
            close(socket_fd);
    }
}

static void handler(int sig) {
    run = false;
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

int stat_iface(ethlog_t *ethlog, char *iface) {
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
            stat_iface(ethlog, message.buf);
            break;
        case FLAG_IFACES:
            print_all_iface(ethlog);
            break;
        case FLAG_EXIT:
            run = false;
            break;
    }
}

void send_message(int flag, char *arg) {
    struct iovec iovec;
    struct msghdr msg = {0};
    message_t message;
    message.flag = flag;
    message.fd = socket_fd;
    strcpy(message.buf, arg);
    iovec.iov_base = &message;
    iovec.iov_len = sizeof(message);
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;
    int ret = sendmsg(socket_fd, &msg, 0);
    if (ret != sizeof(message)) {
        if (ret < 0)
            perror("ehtlog: Could not send device address to daemon\n");
        else
            fprintf(stderr, "ehtlog: Could not send device address to daemon completely!\n");
        cleanup();
        exit(EXIT_FAILURE);
    }
    
}

// int main() {
//     ethlog_t ethlog = construct_ethlog();
//     ip_t a = construct_ip("255.255.255.255", 5);
//     ip_t a1 = construct_ip("255.255.255.255", 6);
//     ip_t b = construct_ip("127.0.0.1", 16);
//     ip_t b1 = construct_ip("127.0.0.1", 16);
//     iface_t iface = construct_iface("eth0", 0, NULL, NULL);
//     iface_t *iface1 = push_iface(&ethlog, iface);

//     iface_t some_if = construct_iface("eth1", 0, NULL, NULL);
//     iface_t *some_if2 = push_iface(&ethlog, some_if);

//     iface_t some_if1 = construct_iface("eth2", 0, NULL, NULL);
//     iface_t *some_if12 = push_iface(&ethlog, some_if1);

//     push_ip(iface1, a);
//     push_ip(some_if2, a1);
//     push_ip(iface1, b);
//     push_ip(iface1, b1);
//     push_ip(some_if12, a1);

//     // serializer(&ethlog);

//     ethlog_t ethlog2 = construct_ethlog();
//     deserializer(&ethlog2);

//     for (int i = 0; i < ethlog2.ip_count; i++) {
//         printf("%s: %ld\n", ethlog2.ip[i].ip_str, ethlog2.ip[i].data_count);
//     }

//     // // print_iface_stat(iface1);
//     // // print_iface_stat(some_if2);
//     find_print_iface(&ethlog, "eth0");
//     find_print_iface(&ethlog2, "eth0");
    
//     return 0;
// }

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

void print_usage();

bool parse_args(int argc, char **argv);

int client(int argc, char **argv) {
    if (argc == 1) {
        print_usage();
        return(EXIT_FAILURE);
    }
    ++argv;
    --argc;
    if (!parse_args(argc, argv)) {
        print_usage();
        return(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

void sniffing(ethlog_t *ethlog) {
    if (!ethlog->is_active)
        return;

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

    // printf("%d\n", pcap_activate(ethlog.handler));
    // pcap_loop(ethlog.handler, -1, process, (u_char *)(&ethlog));
    // Test
    // ip_t a = construct_ip("255.255.255.255", 5);
    // ip_t a1 = construct_ip("255.255.255.255", 6);
    // ip_t b = construct_ip("127.0.0.1", 165);
    // ip_t b1 = construct_ip("127.0.0.1", 16);
    // iface_t iface = construct_iface("eth0", 0, NULL, NULL, NULL);
    // iface_t *iface1 = push_iface(&ethlog, iface);

    // iface_t some_if = construct_iface("eth1", 0, NULL, NULL, NULL);
    // iface_t *some_if2 = push_iface(&ethlog, some_if);

    // iface_t some_if1 = construct_iface("eth2", 0, NULL, NULL, NULL);
    // iface_t *some_if12 = push_iface(&ethlog, some_if1);
    // push_ip(iface1, a);
    // push_ip(some_if2, a1);
    // push_ip(iface1, b);
    // push_ip(iface1, b1);
    // push_ip(some_if12, a1);
    // ============

    // deserializer(&ethlog);


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
    cleanup();
    return EXIT_FAILURE;
}

int main(int argc, char **argv) {
    int service = singleton_connect(SOCKET_NAME);
    switch (service) {
        case 0: { /* Daemon */
            signal_action_handler();
            return daemon_server();
        }
        case 1: { /* Client */
            int ret = client(argc, argv);
            sleep(1);
            return ret;
        }
        default:
            cleanup();
            return EXIT_FAILURE;
    }
    cleanup();
    return EXIT_SUCCESS;
}

void print_usage() {
    fprintf(stderr, "Usage: ./ethlog [param 0] [param 1] ...\n\n");
    fprintf(stderr, "\tEnter \"./ethlog --help\" to get list of commands\n\n");
}

void print_help() {
    printf("usage: ./ethlog [param 0] [param 1] ...\n");
    printf( "\n\tstart\t\t\t | starts sniffing\n"
            "\tstop\t\t\t | stops sniffing\n"
            "\tshow [ip] count\t\t | shows count of packets received from ip addess\n"
            "\tselect iface [iface]\t | select interface for sniffing\n"
            "\tstat [iface]\t\t | shows all collected statictics for interface\t\n"
            "\tifaces\t\t | shows existing interfaces\t\n"
            "\texit\t\t | stops daemon processt\n"
            "\t--help\t\t\t | shows usage\n\n"
    );
}

bool parse_args(int argc, char **argv) {
    switch (argc) {
    case 1 : {
        if (strcmp(argv[0], "start") == 0) {
            send_message(FLAG_START, "");
            return true;
        }
        else if (strcmp(argv[0], "stop") == 0) {
            send_message(FLAG_STOP, "");
            return true;
        }
        else if (strcmp(argv[0], "--help") == 0) {
            print_help();
            return true;
        }
        else if (strcmp(argv[0], "exit") == 0) {
            send_message(FLAG_EXIT, "");
            return true;
        }
        else if (strcmp(argv[0], "ifaces") == 0) {
            send_message(FLAG_IFACES, "");
            return true;
        }
        return false;
    } break;
    
    case 2: {
        if (strcmp(argv[0], "stat") == 0) {
            send_message(FLAG_STAT, argv[1]);
            return true;
        }
        return false;
    } break;

    case 3: {
        if (strcmp(argv[0], "show") == 0 && strcmp(argv[2], "count") == 0) {
            if (check_regex(argv[1], ip_pattern)) {
                send_message(FLAG_SHOW, argv[1]);
                return true;
            }
            else {
                fprintf(stderr, "Invalid ip structure\n");
                exit(EXIT_FAILURE);
            }
            return true;
        }
        else if (strcmp(argv[0], "select") == 0 && strcmp(argv[1], "iface") == 0) {
            printf("Selecting interface %s!\n", argv[2]);
            send_message(FLAG_SELECT, argv[2]);
            return true;
        }
        return false;
    } break;

    }
    return false;
}
