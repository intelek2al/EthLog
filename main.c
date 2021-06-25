// // #include <stdio.h>
// // #include <sys/types.h>
// // #include <unistd.h>

// // #include <sys/file.h>
// // #include <errno.h>

// // void mx_daemonizer() {
// //     pid_t demon;
// //     if (demon = fork() != 0 ) {
// //         printf("Pid: %d\n", getpid() + 1);
// //         exit(0);
// //     }
// //     umask(0);
// //     setsid();
// //     close(STDIN_FILENO);
// //     close(STDOUT_FILENO);
// //     close(STDERR_FILENO);
// // }

// // int main(int argc, char *argv[]) {
// //     int pid_file = open("/var/run/ethlog.pid", O_CREAT | O_RDWR, 0666);

// //     int rc = flock(pid_file, LOCK_EX | LOCK_NB);
// //     if(rc) {
// //         if(EWOULDBLOCK == errno) {
// //             printf("H1\n");
// //         }
// //         else printf("H2\n");

// //     }
// //     else {
// //         printf("H\n");
// // }
// //     return 0;
// // }

#include "ehtlog.h"


#define SOCKET_NAME "/tmp/ethlog"

#define DATA_ERROR -1
#define FLAG_EXIT 0
#define FLAG_START 1
#define FLAG_STOP 2
#define FLAG_SHOW 3
#define FLAG_SELECT 4
#define FLAG_STAT 5


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
int test = 0;


// void connect_to_client(int fd, char *name) {
//     struct sockaddr_un addr = {0};

//     addr.sun_family = AF_UNIX;
//     strcpy(addr.sun_path, name);
//     if (connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == 0)
//         printf("Connection back is successful.\n");
// }

int singleton_connect(const char *name) {
    int len, tmpd;
    struct sockaddr_un addr = {0};

    if ((tmpd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
        printf("Could not create socket: '%s'.\n", strerror(errno));
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
                printf("Pid: %d\n", getpid() + 1);
                exit(0);
            }
            umask(0);
            setsid();
            return 0;
        } else {
            if (errno == EADDRINUSE) {
                ret = connect(tmpd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
                if (ret != 0) {
                    printf("Socket %d\n", tmpd);
                    if (errno == ECONNREFUSED) {
                        printf("Could not connect to socket - assuming daemon died.\n");
                        unlink(name);
                        continue;
                    }
                    printf("Could not connect to socket: '%s'.\n", strerror(errno));
                    continue;
                }
                // printf("Daemon is already running.\n");
                socket_fd = tmpd;
                return 1;
            }
            printf("Could not bind to socket: '%s'.\n", strerror(errno));
            continue;
        }
    } while (retries-- > 0);

    printf("Could neither connect to an existing daemon nor become one.\n");
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

int select_iface(ethlog_t *ethlog, char *ip) {
    printf("select_iface");
    return 0;
}

int stat_iface(ethlog_t *ethlog, char *iface) {
    find_print_iface(ethlog, iface);
    return 0;
}

void request_handler(ethlog_t *ethlog, message_t message) {
    switch (message.flag) {   
        case FLAG_START:
            ethlog->is_active = true;
            break;
        case FLAG_STOP:
            ethlog->is_active = false;
            break;
        case FLAG_SHOW:
            show_count(ethlog, message.buf);
        case FLAG_SELECT:
            select_iface(ethlog, message.buf);
            break;
        case FLAG_STAT:
            stat_iface(ethlog, message.buf);
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
            printf("Could not send device address to daemon: '%s'!\n", strerror(errno));
        else
            printf("Could not send device address to daemon completely!\n");
        cleanup();
        exit(EXIT_FAILURE);
    }
    
}


int main() {
    ethlog_t ethlog = construct_ethlog();
    ip_t a = construct_ip("255.255.255.255", 5);
    ip_t a1 = construct_ip("255.255.255.255", 6);
    ip_t b = construct_ip("127.0.0.1", 16);
    ip_t b1 = construct_ip("127.0.0.1", 16);
    iface_t iface = construct_iface("eth0", 0, NULL, NULL);
    iface_t *iface1 = push_iface(&ethlog, iface);

    iface_t some_if = construct_iface("eth1", 0, NULL, NULL);
    iface_t *some_if2 = push_iface(&ethlog, some_if);

    iface_t some_if1 = construct_iface("eth2", 0, NULL, NULL);
    iface_t *some_if12 = push_iface(&ethlog, some_if1);

    push_ip(iface1, a);
    push_ip(some_if2, a1);
    push_ip(iface1, b);
    push_ip(iface1, b1);
    push_ip(some_if12, a1);

    // serializer(&ethlog);

    ethlog_t ethlog2 = construct_ethlog();
    deserializer(&ethlog2);

    for (int i = 0; i < ethlog2.ip_count; i++) {
        printf("%s: %ld\n", ethlog2.ip[i].ip_str, ethlog2.ip[i].data_count);
    }

    // // print_iface_stat(iface1);
    // // print_iface_stat(some_if2);
    find_print_iface(&ethlog2, "eth0");
    
    return 0;
}



void signal_action_handler() {
    struct sigaction sigact;
    sigact.sa_handler = &handler;
    sigemptyset(&sigact.sa_mask);
    if (sigaction(SIGINT, &sigact, NULL) != 0 || sigaction(SIGQUIT, &sigact, NULL) != 0 || sigaction(SIGTERM, &sigact, NULL) != 0) {
        printf("Could not set up signal handlers!\n");
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

    

    serializer(ethlog);
}

int daemon_server() {
    ethlog_t ethlog = construct_ethlog();
    struct msghdr msg = {0};
    struct iovec iovec;
    message_t client_message;
    iovec.iov_base = &client_message;
    iovec.iov_len = sizeof(client_message);
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;

    // Test
    // ip_t a = construct_ip("255.255.255.255", 5);
    // ip_t a1 = construct_ip("255.255.255.255", 6);
    // ip_t b = construct_ip("127.0.0.1", 165);
    // ip_t b1 = construct_ip("127.0.0.1", 16);
    // iface_t iface = construct_iface("eth0", 0, NULL, NULL);
    // iface_t *iface1 = push_iface(&ethlog, iface);

    // iface_t some_if = construct_iface("eth1", 0, NULL, NULL);
    // iface_t *some_if2 = push_iface(&ethlog, some_if);

    // iface_t some_if1 = construct_iface("eth2", 0, NULL, NULL);
    // iface_t *some_if12 = push_iface(&ethlog, some_if1);
    // push_ip(iface1, a);
    // push_ip(some_if2, a1);
    // push_ip(iface1, b);
    // push_ip(iface1, b1);
    // push_ip(some_if12, a1);
    // ============

    deserializer(&ethlog);

    while (run) {
        sniffing(&ethlog);
        int ret = recvmsg(socket_fd, &msg, MSG_DONTWAIT);
        if (ret != sizeof(client_message)) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("Error while accessing socket: %s\n", strerror(errno));
                exit(1);
            }
        } else {
            request_handler(&ethlog, client_message);
            // printf("received client_arg=%s %d\n", client_message.buf, getpid());
        }
    }
    printf("ehtlog: Daemon is terminated!\n");
    cleanup();
    return EXIT_FAILURE;
}

// int main(int argc, char **argv) {
//     int service = singleton_connect(SOCKET_NAME);
//     switch (service) {
//         case 0: { /* Daemon */
//             signal_action_handler();
//             return daemon_server();
//         }
//         case 1: { /* Client */
//             return client(argc, argv);
//         }
//         default:
//             cleanup();
//             return EXIT_FAILURE;
//     }
//     cleanup();
//     return EXIT_SUCCESS;
// }


// //  ***************** EXTRA ****************
// char *strnew(const int size) {
//     char *ptrVar = NULL;

//     if (size >= 0) {
//         if ((ptrVar = malloc((size + 1) * sizeof(char))) == NULL)
//             return NULL;
//         else  {        
//             for (int i = 0; i <= size; i++) 
//                 ptrVar[i] = '\0';            
//         }
//         return ptrVar;
//     }
//     return NULL;     
// }

// char *strdup(const char *s1) {
//     char *arr = strnew(strlen(s1));

//     for (int i = 0; i < strlen(s1); i++) {
//         arr[i] = s1[i];
//     }
//     arr[strlen(s1)] = '\0';
//     return arr;
// }

// char *strjoin(const char *s1, const char *s2) {
//     char *result = NULL;

//     if (!s1 && !s2) 
//         return NULL;
//     if (!s2) 
//         return strdup(s1);
//     if (!s1) 
//         return strdup(s2);
//     result = strcat(strcpy(strnew(strlen(s1) + strlen(s2)), s1), s2);
//     return result;
// }

//  ***************** EXTRA ****************

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
            "\t--help\t\t\t | shows usage\n\n"
    );
}

bool parse_args(int argc, char **argv) {
    switch (argc) {
    case 1 : {
        if (strcmp(argv[0], "start") == 0) {
            send_message(FLAG_START, "");
            // printf("Start!\n");
            return true;
        }
        else if (strcmp(argv[0], "stop") == 0) {
            send_message(FLAG_STOP, "");
            // printf("Stop!\n");
            return true;
        }
        else if (strcmp(argv[0], "--help") == 0) {
            print_help();
            return true;
        }
        else if (strcmp(argv[0], "exit") == 0) {
            send_message(FLAG_EXIT, "");
            // printf("Stop!\n");
            return true;
        }
        return false;
    } break;
    
    case 2: {
        if (strcmp(argv[0], "stat") == 0) {
            // printf("Showing status of %s!\n", argv[1]);
            send_message(FLAG_STAT, argv[1]);
            return true;
        }
        return false;
    } break;

    case 3: {
        if (strcmp(argv[0], "show") == 0 && strcmp(argv[2], "count") == 0) {
            if (check_regex(argv[1], ip_pattern)) {
                // printf("Showing data of ip: %s\n", argv[1]);
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
