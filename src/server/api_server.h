#ifndef API_SERVER_H
#define API_SERVER_H

#include <time.h>

#include "core/object_types.h"
#include "auth/auth.h"
#include "config/config_parser.h"

struct MHD_Daemon;
struct RateLimiter;

typedef struct ApiServer
{
    struct MHD_Daemon*  daemon;
    ObjectStore*        store;
    TokenStore*         tokens;
    const char*         cors_origin;
    const char*         temporary_directory;
    struct RateLimiter* api_limiter;
    struct RateLimiter* auth_limiter;
    time_t              start_time;
} ApiServer;

ApiServer* api_server_start(unsigned int port, const char* cors_origin,
                            const char* temporary_directory, ObjectStore* store, TokenStore* tokens,
                            const RateLimitConfig* api_rate_limit,
                            const RateLimitConfig* auth_rate_limit, int tls_enabled,
                            const char* tls_cert_path, const char* tls_key_path);

void api_server_stop(ApiServer* server);

#endif