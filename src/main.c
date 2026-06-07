#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "obj_operations.h"
#include "api_server.h"

#define DEFAULT_PORT 8080

static volatile int running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
    unsigned int port = DEFAULT_PORT;
    if (argc == 2)
        port = (unsigned int)atoi(argv[1]);

    printf("Welcome to X2S — eXtremely Simple Storage\n");

    ObjectStore *store = create_store(16, "./x2s_data");
    if (!store) {
        fprintf(stderr, "Failed to create object store\n");
        return 1;
    }

    ApiServer *api = api_server_start(port, store);
    if (!api) {
        fprintf(stderr, "Failed to start API server on port %u\n", port);
        free_store(store);
        return 1;
    }

    printf("Listening on http://0.0.0.0:%u\n", port);
    printf("  PUT    /objects            upload an object\n");
    printf("  GET    /objects/<id>       retrieve an object\n");
    printf("  DELETE /objects/<id>       remove an object\n");
    printf("Press Ctrl-C to stop.\n\n");

    signal(SIGINT, handle_sigint);
    while (running) sleep(1);

    printf("\nShutting down...\n");
    api_server_stop(api);
    free_store(store);
    return 0;
}