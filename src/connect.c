#include "connect.h"

int socket_fd = -1;
bool isdaemon = false;
bool run = true;

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

void cleanup(void) {
    if (socket_fd >= 0) {
        if (isdaemon) {
            if (unlink(SOCKET_NAME) < 0)
                printf("Could not remove FIFO.\n");
        } else
            close(socket_fd);
    }
}