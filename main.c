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

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SOCKET_NAME "/tmp/ethlog"


#define IFACE_MAX_COUNT 256
#define IFACE_BUF_SIZE 128

#define IP_MAX_COUNT 256
#define IP_BUF_SIZE 16

#define DATA_ERROR -1
#define FLAG_START 1
#define FLAG_STOP 2
#define FLAG_SHOW 3
#define FLAG_SELECT 4
#define FLAG_STAT 5

struct ip_s {
    int size;
    char ip_str[IP_BUF_SIZE];
    int data_count;
} typedef ip_t;

struct iface_s {
    int ip_count;
    char iface_str[IFACE_BUF_SIZE];
    ip_t ip[IP_MAX_COUNT];
} typedef iface_t;

struct ethlog_s {
    int iface_count;
    int iface_current;
    iface_t iface[IFACE_MAX_COUNT];
} typedef ethlog_t;

void serializer(ethlog_t *data) {
    FILE *fd = fopen("/var/run/ethlog", "w");
    fwrite(data, sizeof(ethlog_t), sizeof(ethlog_t), fd);
    fclose(fd);
}

ethlog_t deserializer() {
    
}

static int count_packet(iface_t *iface) {
    int buf = 0;
    for (int i = 0; i < iface->ip_count; i++) {
        buf += iface->ip[i].data_count;
    }
    return buf;
}

void print_iface_stat(iface_t *iface) {
    printf("Common info of interface \"%s\":\n\n", iface->iface_str);
    printf("\t IPs count -- %d;\n", iface->ip_count);
    printf("\t Packets were received -- %d\n\n", count_packet(iface));
    for (int i = 0; i < iface->ip_count; i++) {
        printf("\tIP \"%s\": %d packet(s)", iface->ip[i].ip_str, iface->ip[i].data_count);
    }
}

struct message_t {
    int fd;
    int flag;
    char buf[256];
};

static int socket_fd = -1;
static bool isdaemon = false;
static bool run = true;
int test = 0;


void connect_to_client(int fd, char *name) {
    int len;
    struct sockaddr_un addr = {0};

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, name);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(name);
    int ret;
    ret = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    if (ret == 0)
        printf("Connection back is successful.\n");
}

int singleton_connect(const char *name) {
    int len, tmpd;
    struct sockaddr_un addr = {0};

    if ((tmpd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
        printf("Could not create socket: '%s'.\n", strerror(errno));
        return -1;
    }
    printf("!!!! Socket is %d\n", tmpd);

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
                    if (errno == ECONNREFUSED) {
                        printf("Could not connect to socket - assuming daemon died.\n");
                        unlink(name);
                        continue;
                    }
                    printf("Could not connect to socket: '%s'.\n", strerror(errno));
                    continue;
                }
                printf("Daemon is already running.\n");
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

int show_count(char *ip) {
    printf("Show");
    return 0;
}

int select_iface(char *ip) {
    printf("select_iface");
    return 0;
}

int stat_iface(char *ip) {
    printf("stat_iface");
    return 0;
}

int flag_parser(struct message_t message) {
    switch (message.flag) {        
    case FLAG_SHOW:
        return show_count(message.buf);
    case FLAG_SELECT:
        return select_iface(message.buf);
        break;
    case FLAG_STAT:
        return stat_iface(message.buf);
        break;
    default:
        return DATA_ERROR;
    }
}

void send_message(int flag, char *arg) {
    struct iovec iovec;
    struct msghdr msg = {0};
    struct message_t message;
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
    iface_t iface;
    print_iface_stat(&iface);
    return 0;
}

// int main(int argc, char **argv) {
//     switch (singleton_connect(SOCKET_NAME)) {
//         case 0: { /* Daemon */
//             struct sigaction sa;
//             sa.sa_handler = &handler;
//             sigemptyset(&sa.sa_mask);
//             if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGQUIT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
//                 printf("Could not set up signal handlers!\n");
//                 cleanup();
//                 return EXIT_FAILURE;
//             }

//             struct msghdr msg = {0};
//             struct iovec iovec;
//             struct message_t client_message;
//             iovec.iov_base = &client_message;
//             iovec.iov_len = sizeof(client_message);
//             msg.msg_iov = &iovec;
//             msg.msg_iovlen = 1;

//             while (run) {
//                 int ret = recvmsg(socket_fd, &msg, MSG_DONTWAIT);
//                 if (ret != sizeof(client_message)) {
//                     if (errno != EAGAIN && errno != EWOULDBLOCK) {
//                         printf("Error while accessing socket: %s\n", strerror(errno));
//                         exit(1);
//                     }
//                     // printf("No further client_args in socket.\n");
//                 } else {
//                     flag_parser(client_message);
//                     printf("received client_arg=%s\n", client_message.buf);
//                 }
//                 sleep(1);
//             }
//             printf("Dropped out of daemon loop. Shutting down.\n");
//             cleanup();
//             return EXIT_FAILURE;
//         }
//         case 1: { /* Client */
//             if (argc < 2) {
//                 printf("Usage: %s <int>\n", argv[0]);
//                 return EXIT_FAILURE;
//             }
//             send_message(1, argv[1]);
//             struct msghdr resp = {0};
//             sleep(1);
//             // // if (ret_res <)
//             // struct message *resp_mess = (struct message *)(resp.msg_iov->iov_base);
//             // printf("Respond (%d) from server ", ret_res);
//             // printf("(%s) to client.\n", resp_mess->buf);
//             // struct iovec iovec;
//             // struct msghdr msg = {0};
//             // struct message message;
//             // strcpy(message.buf, argv[1]);
//             // iovec.iov_base = &message;
//             // iovec.iov_len = sizeof(message);
//             // msg.msg_iov = &iovec;
//             // msg.msg_iovlen = 1;
//             // int ret = sendmsg(socket_fd, &msg, 0);
//             // if (ret != sizeof(message)) {
//             //     if (ret < 0)
//             //         printf("Could not send device address to daemon: '%s'!\n", strerror(errno));
//             //     else
//             //         printf("Could not send device address to daemon completely!\n");
//             //     cleanup();
//             //     return EXIT_FAILURE;
//             // }
//             // printf("Sent client_arg (%s) to daemon.\n", message.buf);
//             break;
//         }
//         default:
//             cleanup();
//             return EXIT_FAILURE;
//     }

//     cleanup();
//     return EXIT_SUCCESS;
// }




// #include <stdio.h>
// #include <stddef.h>
// #include <stdbool.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <errno.h>
// #include <sys/types.h>
// #include <signal.h>
// #include <sys/socket.h>
// #include <sys/un.h>
// #include <regex.h>
// #include <string.h>

// static char *ip_pattern = "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
//          "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
//          "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
//          "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$";

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

// //  ***************** EXTRA ****************

// void print_usage() {
//     fprintf(stderr, "Usage: ./ethlog [param 0] [param 1] ...\n\n");
//     fprintf(stderr, "\tEnter \"./ethlog --help\" to get list of commands\n\n");
// }

// bool check_regex(char *str, char *pattern) {
//     regex_t regex;
//     const int n_matches = 3;
//     regmatch_t match[n_matches];
//     int return_value = 1;
//     if (regcomp(&regex, pattern, REG_EXTENDED) == 0) {
//         return_value = regexec(&regex, str, n_matches, match, 0);
//     }
//     regfree(&regex);
//     return return_value == 0;
// }

// void print_help() {
//     printf("usage: ./ethlog [param 0] [param 1] ...\n");
//     printf( "\n\tstart\t\t\t | starts sniffing\n"
//             "\tstop\t\t\t | stops sniffing\n"
//             "\tshow [ip] count\t\t | shows count of packets received from ip addess\n"
//             "\tselect iface [iface]\t | select interface for sniffing\n"
//             "\tstat [iface]\t\t | shows all collected statictics for interface\t\n"
//             "\t--help\t\t\t | shows usage\n\n"
//     );
// }

// #define BUFSIZE 256

// void end() {
//     exit(0);
// }

// void listener(){
//     int fd[2];
//     if (pipe(fd) == -1) {
//         printf("Unfortunate pipe\n");
//     }

//     pid_t child_pid = fork();
//     if (child_pid < 0) {
//         printf("Bad forking!\n");
//         exit(1);
//     }
//     if (child_pid == 0) { // daemon
//     char message[BUFSIZE];
//     strcpy(message, "Hello");
//         printf("Child pid: %d", getpid());
//         signal(SIGUSR1, end);
//         int i = 0;
//         while (i++ < 7) {
//             while (read(fd[0], message, BUFSIZE) < 0)
//                 printf("Do\n");
//             sleep(1);
//             write(fd[1], message, BUFSIZE);
//             if (errno != EAGAIN && errno != EWOULDBLOCK) {
//                 printf("Error while accessing socket: %s\n", strerror(errno));
//                 exit(1);
//             }
//         }
//         exit(0);
//     }
//     else {
//         char message[BUFSIZE];
//         printf("Parent!\n");
//         read(fd[0], message, BUFSIZE);
//         if (errno != EAGAIN && errno != EWOULDBLOCK) {
//             printf("Error while accessing socket: %s\n", strerror(errno));
//             exit(1);
//         }
//         printf("Message is: %s\n", message);
//         kill(child_pid, SIGUSR1);

//     }
// }


// bool parse_args(int argc, char **argv) {
//     switch (argc)
//     {
//     case 1 : {
//         if (strcmp(argv[0], "start") == 0) {
//             listener();
//             printf("Start!\n");
//             return true;
//         }
//         else if (strcmp(argv[0], "stop") == 0) {
//             printf("Stop!\n");
//             return true;
//         }
//         else if (strcmp(argv[0], "--help") == 0) {
//             print_help();
//             return true;
//         }
//         return false;
//     } break;
    
//     case 2: {
//         if (strcmp(argv[0], "stat") == 0) {
//             printf("Showing status of %s!\n", argv[1]);
//             return true;
//         }
//         return false;
//     } break;

//     case 3: {
//         if (strcmp(argv[0], "show") == 0 && strcmp(argv[2], "count") == 0) {
//             if (check_regex(argv[1], ip_pattern)) {
//                 printf("Showing data of ip: %s\n", argv[1]);
//                 return true;
//             }
//             else {
//                 fprintf(stderr, "Invalid ip structure\n");
//                 exit(EXIT_FAILURE);
//             }
//             return true;
//         }
//         else if (strcmp(argv[0], "select") == 0 && strcmp(argv[1], "iface") == 0) {
//             printf("Selecting interface %s!\n", argv[2]);
//             return true;
//         }
//         return false;
//     } break;

//     }
    
// }

// int main(int argc, char *argv[]) {
//     if (argc == 1) {
//         print_usage();
//         exit(EXIT_FAILURE);
//     }
//     ++argv;
//     --argc;
//     if (!parse_args(argc, argv)) {
//         print_usage();
//         exit(EXIT_FAILURE);
//     }
//     return 0;
// }
