#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdio.h>
#include <stddef.h>

typedef struct
{
    size_t   capacity;
    size_t   refill_rate;
    unsigned refill_interval_ms;
    size_t   bucket_count;
} RateLimitConfig;

typedef struct
{
    unsigned int port;
    char         cors_origin[4096];
    char         data_directory[4096];
    char         temporary_directory[4096];
    char         master_key[128];
    int          rate_limit_enabled;
    RateLimitConfig rate_limit_api;
    RateLimitConfig rate_limit_auth;
} CliConfig;

int cli_setup_parse(int argc, char* const argv[], CliConfig* config);
int cli_setup_read_config(FILE* input, CliConfig* config);

#endif
