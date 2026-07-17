#include "server/api_server.h"
#include "server/rate_limiter.h"
#include "auth/auth.h"
#include "config/config_parser.h"
#include "storage/object_repository.h"
#include "core/hex_utils.h"
#include "crypto/encryption.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Sleep duration in microseconds (100000 us = 100 ms) */
#define MAIN_SLEEP_US 100000

static volatile int running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char* argv[])
{
    CliConfig config;

    if (cli_setup_parse(argc, argv, &config) != 0) {
        return 1;
    }

    unsigned int port        = config.port;
    const char*  cors_origin = config.cors_origin;

    printf("Welcome to X2S — eXtremely Simple Storage\n");

    /* Ensure temporary directory exists */
    if (mkdir(config.temporary_directory, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create temporary directory: %s\n", config.temporary_directory);
        return 1;
    }

    ObjectStore* store = create_store(16, config.data_directory);
    if (!store) {
        fprintf(stderr, "Failed to create object store\n");
        return 1;
    }

    UserStore* users = user_store_create(8);
    if (!users) {
        fprintf(stderr, "Failed to create user store\n");
        free_store(store);
        return 1;
    }

    int ulr = user_store_load(users, store->store_path);
    if (ulr == -1) {
        fprintf(stderr, "error: __users has an unrecognized format version. "
                        "Run x2s-migrate to upgrade.\n");
        user_store_free(users);
        free_store(store);
        return 1;
    }

    SessionStore* sessions = session_store_create(16);
    if (!sessions) {
        fprintf(stderr, "Failed to create session store\n");
        user_store_free(users);
        free_store(store);
        return 1;
    }

    TokenStore tokens = {.users = users, .sessions = sessions};

    RateLimitConfig* api_rate  = config.rate_limit_enabled ? &config.rate_limit_api : NULL;
    RateLimitConfig* auth_rate = config.rate_limit_enabled ? &config.rate_limit_auth : NULL;

    ApiServer* api =
        api_server_start(port, cors_origin, config.temporary_directory, store, &tokens,
                         api_rate, auth_rate);
    if (!api) {
        fprintf(stderr, "Failed to start API server on port %u\n", port);
        session_store_free(sessions);
        user_store_free(users);
        free_store(store);
        return 1;
    }

    printf("Listening on http://0.0.0.0:%u\n", port);
    printf("Allowed CORS Origin: %s\n", cors_origin);
    printf("Data directory: %s\n", config.data_directory);
    printf("Temporary directory: %s\n", config.temporary_directory);
    printf("Encryption at rest: %s\n", encryption_is_active() ? "enabled" : "disabled");
    printf("  POST  /auth/register      register a new user\n");
    printf("  POST  /auth/login          authenticate and get a token\n");
    printf("  POST  /auth/logout         invalidate a token\n");
    printf("  POST  /objects             upload an object\n");
    printf("  GET   /objects             list owned objects\n");
    printf("  GET   /objects/<id>        retrieve an object\n");
    printf("  DELETE /objects/<id>       remove an object\n");
    printf("  POST  /objects/<id>/share  share an object with another user\n");
    printf("Press Ctrl-C to stop.\n\n");

    signal(SIGINT, handle_sigint);
    while (running) {
        usleep(MAIN_SLEEP_US);
        check_token_expiry(sessions);
        if (api->api_limiter)
            rate_limiter_cleanup(api->api_limiter);
        if (api->auth_limiter)
            rate_limiter_cleanup(api->auth_limiter);
    }

    printf("\nShutting down...\n");
    api_server_stop(api);
    user_store_save(users, store->store_path);
    session_store_free(sessions);
    user_store_free(users);
    free_store(store);
    return 0;
}
