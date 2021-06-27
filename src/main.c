#include "daemon.h"
#include "ehtlog.h"
#include "client.h"


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
