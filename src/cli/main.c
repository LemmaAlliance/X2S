#include "server/api_server.h"
#include "server/rate_limiter.h"
#include "auth/auth.h"
#include "auth/token.h"
#include "auth/refresh_token.h"
#include "config/config_parser.h"
#include "storage/object_repository.h"
#include "core/hex_utils.h"
#include "crypto/encryption.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
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

    unsigned char hmac_key[HMAC_KEY_SIZE];
    if (!generate_hmac_key(hmac_key)) {
        fprintf(stderr, "Failed to generate HMAC key\n");
        user_store_free(users);
        free_store(store);
        return 1;
    }

    RefreshTokenStore* refresh_tokens = refresh_token_store_create(16);
    if (!refresh_tokens) {
        fprintf(stderr, "Failed to create refresh token store\n");
        user_store_free(users);
        free_store(store);
        return 1;
    }

    RevocationStore* revoked_access = revocation_store_create(16);
    if (!revoked_access) {
        fprintf(stderr, "Failed to create revocation store\n");
        refresh_token_store_free(refresh_tokens);
        user_store_free(users);
        free_store(store);
        return 1;
    }

    refresh_token_store_load(refresh_tokens, store->store_path);

    TokenStore tokens = {.users = users, .refresh_tokens = refresh_tokens,
                         .revoked_access = revoked_access};
    memcpy(tokens.hmac_key, hmac_key, HMAC_KEY_SIZE);

    RateLimitConfig* api_rate  = config.rate_limit_enabled ? &config.rate_limit_api : NULL;
    RateLimitConfig* auth_rate = config.rate_limit_enabled ? &config.rate_limit_auth : NULL;

    ApiServer* api =
        api_server_start(port, cors_origin, config.temporary_directory, store, &tokens, api_rate,
                         auth_rate, config.tls_enabled, config.tls_cert_path, config.tls_key_path);
    if (!api) {
        fprintf(stderr, "Failed to start API server on port %u\n", port);
        refresh_token_store_free(refresh_tokens);
        revocation_store_destroy(revoked_access);
        user_store_free(users);
        free_store(store);
        return 1;
    }

    printf("Listening on %s://0.0.0.0:%u\n", config.tls_enabled ? "https" : "http", port);
    printf("Allowed CORS Origin: %s\n", cors_origin);
    printf("Data directory: %s\n", config.data_directory);
    printf("Temporary directory: %s\n", config.temporary_directory);
    printf("Encryption at rest: %s\n", encryption_is_active() ? "enabled" : "disabled");
    printf("TLS: %s\n", config.tls_enabled ? "enabled" : "disabled");
    printf("  POST  /auth/register      register a new user\n");
    printf("  POST  /auth/login          authenticate and get a token\n");
    printf("  POST  /auth/refresh        refresh an expired token\n");
    printf("  POST  /auth/logout         invalidate tokens\n");
    printf("  POST  /objects             upload an object\n");
    printf("  GET   /objects             list owned objects\n");
    printf("  GET   /objects/<id>        retrieve an object\n");
    printf("  DELETE /objects/<id>       remove an object\n");
    printf("  GET   /health               health check endpoint\n");
    printf("  POST  /objects/<id>/share  share an object with another user\n");
    printf("Press Ctrl-C to stop.\n\n");

    signal(SIGINT, handle_sigint);
    while (running) {
        usleep(MAIN_SLEEP_US);
        revocation_store_cleanup(revoked_access);
        refresh_token_cleanup(refresh_tokens);
        if (api->api_limiter)
            rate_limiter_cleanup(api->api_limiter);
        if (api->auth_limiter)
            rate_limiter_cleanup(api->auth_limiter);
    }

    printf("\nShutting down...\n");
    api_server_stop(api);
    user_store_save(users, store->store_path);
    refresh_token_store_save(refresh_tokens, store->store_path);
    refresh_token_store_free(refresh_tokens);
    revocation_store_destroy(revoked_access);
    user_store_free(users);
    free_store(store);
    return 0;
}
