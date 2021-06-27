#ifndef CONNECT_H
#define CONNECT_H

#include "main.h"

struct message_s {
    int fd;
    int flag;
    char buf[64];
} typedef message_t;

void send_message(int flag, char *arg);

int singleton_connect(const char *name);

void cleanup(void);

#endif