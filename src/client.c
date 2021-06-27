#include "client.h"
#include "connect.h"
#include "ip.h"

extern int socket_fd;
extern bool isdaemon;
extern bool run;

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
        else if (strcmp(argv[0], "stat") == 0) {
            send_message(FLAG_STAT_ALL, "");
            return true;
        }
        else if (strcmp(argv[0], "clear") == 0) {
            send_message(FLAG_CLEAR, "");
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
            "\tstat \t\t\t | shows all collected statictics for each interface\t\n"
            "\tclear \t\t\t | resets all data\t\n"
            "\tifaces\t\t\t | shows existing interfaces\t\n"
            "\texit\t\t\t | stops daemon process\n"
            "\t--help\t\t\t | shows usage\n\n"
    );
}

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
