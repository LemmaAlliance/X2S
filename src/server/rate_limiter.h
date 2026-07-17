#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    size_t capacity;
    size_t refill_rate;
    unsigned refill_interval_ms;
} RateLimitZoneConfig;

typedef struct RateLimiter RateLimiter;

RateLimiter* rate_limiter_create(RateLimitZoneConfig config, size_t bucket_count);
int rate_limiter_allow(RateLimiter* limiter, const char* client_ip);
void rate_limiter_cleanup(RateLimiter* limiter);
void rate_limiter_destroy(RateLimiter* limiter);

#endif
