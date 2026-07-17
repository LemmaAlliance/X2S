#define _POSIX_C_SOURCE 200809L
#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STALE_TIMEOUT_MS 10000

typedef struct Bucket
{
    char*           client_ip;
    double          tokens;
    uint64_t        last_refill_ms;
    struct Bucket*  next;
} Bucket;

struct RateLimiter
{
    RateLimitZoneConfig config;
    Bucket**            buckets;
    size_t              bucket_count;
    uint64_t            last_cleanup_ms;
};

static uint64_t current_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static size_t hash_ip(const char* ip, size_t bucket_count)
{
    size_t hash = 5381;
    for (const char* p = ip; *p; p++)
        hash = ((hash << 5) + hash) + (unsigned char)*p;
    return hash % bucket_count;
}

static Bucket* bucket_create(const char* client_ip, size_t capacity, uint64_t now_ms)
{
    Bucket* b = calloc(1, sizeof(Bucket));
    if (!b)
        return NULL;
    b->client_ip = strdup(client_ip);
    if (!b->client_ip) {
        free(b);
        return NULL;
    }
    b->tokens         = (double)capacity;
    b->last_refill_ms = now_ms;
    return b;
}

static void bucket_destroy(Bucket* b)
{
    free(b->client_ip);
    free(b);
}

static void bucket_refill(Bucket* b, const RateLimitZoneConfig* config, uint64_t now_ms)
{
    uint64_t elapsed = now_ms - b->last_refill_ms;
    if (elapsed < config->refill_interval_ms)
        return;

    double gained = (double)elapsed / config->refill_interval_ms * config->refill_rate;
    b->tokens      = b->tokens + gained;
    b->tokens      = b->tokens > (double)config->capacity ? (double)config->capacity : b->tokens;
    b->last_refill_ms = now_ms;
}

RateLimiter* rate_limiter_create(RateLimitZoneConfig config, size_t bucket_count)
{
    RateLimiter* limiter = calloc(1, sizeof(RateLimiter));
    if (!limiter)
        return NULL;

    limiter->buckets = calloc(bucket_count, sizeof(Bucket*));
    if (!limiter->buckets) {
        free(limiter);
        return NULL;
    }

    limiter->config         = config;
    limiter->bucket_count   = bucket_count;
    limiter->last_cleanup_ms = current_time_ms();
    return limiter;
}

int rate_limiter_allow(RateLimiter* limiter, const char* client_ip)
{
    size_t   idx    = hash_ip(client_ip, limiter->bucket_count);
    uint64_t now_ms = current_time_ms();
    Bucket*  b      = limiter->buckets[idx];

    while (b) {
        if (strcmp(b->client_ip, client_ip) == 0)
            break;
        b = b->next;
    }

    if (!b) {
        b = bucket_create(client_ip, limiter->config.capacity, now_ms);
        if (!b)
            return 1;
        b->next           = limiter->buckets[idx];
        limiter->buckets[idx] = b;
    }

    bucket_refill(b, &limiter->config, now_ms);

    if (b->tokens >= 1.0) {
        b->tokens -= 1.0;
        return 1;
    }

    return 0;
}

void rate_limiter_cleanup(RateLimiter* limiter)
{
    if (!limiter)
        return;

    uint64_t now_ms    = current_time_ms();
    uint64_t threshold = now_ms > STALE_TIMEOUT_MS ? now_ms - STALE_TIMEOUT_MS : 0;

    if (now_ms - limiter->last_cleanup_ms < 5000)
        return;

    limiter->last_cleanup_ms = now_ms;

    for (size_t i = 0; i < limiter->bucket_count; i++) {
        Bucket** prev = &limiter->buckets[i];
        Bucket*  cur  = limiter->buckets[i];

        while (cur) {
            Bucket* next = cur->next;
            if (cur->last_refill_ms < threshold && cur->tokens >= (double)limiter->config.capacity) {
                *prev = next;
                bucket_destroy(cur);
            } else {
                prev = &cur->next;
            }
            cur = next;
        }
    }
}

void rate_limiter_destroy(RateLimiter* limiter)
{
    if (!limiter)
        return;

    for (size_t i = 0; i < limiter->bucket_count; i++) {
        Bucket* cur = limiter->buckets[i];
        while (cur) {
            Bucket* next = cur->next;
            bucket_destroy(cur);
            cur = next;
        }
    }

    free(limiter->buckets);
    free(limiter);
}
