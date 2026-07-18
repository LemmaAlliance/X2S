#include "config/config_parser.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cJSON.h"
#include "core/hex_utils.h"
#include "crypto/encryption.h"

#define DEFAULT_PORT 8080
#define DEFAULT_CORS "*"
#define DEFAULT_DATA_DIRECTORY "./x2s_data"
#define DEFAULT_TEMP_DIRECTORY "/tmp/x2s"

/* Use cJSON for parsing instead of manual string extraction. */

static int read_json_stream(FILE* input, char** buffer_out)
{
    char   chunk[256];
    char*  buffer   = NULL;
    size_t length   = 0;
    size_t capacity = 0;

    if (!input || !buffer_out) {
        return 1;
    }

    while (fgets(chunk, sizeof(chunk), input) != NULL) {
        size_t chunk_len = strlen(chunk);
        if (length + chunk_len + 1 > capacity) {
            size_t new_capacity = capacity == 0 ? 1024 : capacity * 2;
            while (new_capacity < length + chunk_len + 1) {
                new_capacity *= 2;
            }

            char* new_buffer = realloc(buffer, new_capacity);
            if (!new_buffer) {
                free(buffer);
                return 1;
            }

            buffer   = new_buffer;
            capacity = new_capacity;
        }

        memcpy(buffer + length, chunk, chunk_len);
        length += chunk_len;
    }

    if (ferror(input)) {
        free(buffer);
        return 1;
    }

    if (!buffer) {
        buffer = malloc(1);
        if (!buffer) {
            return 1;
        }
    }

    buffer[length] = '\0';
    *buffer_out    = buffer;
    return 0;
}

static void parse_rate_limit_zone(cJSON* zone, RateLimitConfig* cfg)
{
    if (!cJSON_IsObject(zone))
        return;

    cJSON* capacity_item = cJSON_GetObjectItemCaseSensitive(zone, "capacity");
    if (cJSON_IsNumber(capacity_item))
        cfg->capacity = (size_t)capacity_item->valueint;

    cJSON* refill_rate_item = cJSON_GetObjectItemCaseSensitive(zone, "refill_rate");
    if (cJSON_IsNumber(refill_rate_item))
        cfg->refill_rate = (size_t)refill_rate_item->valueint;

    cJSON* interval_item = cJSON_GetObjectItemCaseSensitive(zone, "refill_interval_ms");
    if (cJSON_IsNumber(interval_item))
        cfg->refill_interval_ms = (unsigned)interval_item->valueint;

    cJSON* bucket_count_item = cJSON_GetObjectItemCaseSensitive(zone, "bucket_count");
    if (cJSON_IsNumber(bucket_count_item))
        cfg->bucket_count = (size_t)bucket_count_item->valueint;
}

int cli_setup_read_config(FILE* input, CliConfig* config)
{
    const char* data_keys[] = {"data_directory", "data_dir", "dataDirectory"};
    const char* temp_keys[] = {"temporary_directory", "temporary_dir", "temp_directory", "temp_dir",
                               "temporaryDirectory",  "tempDirectory"};
    const char* cors_keys[] = {"cors_origin", "corsOrigin"};
    const char* key_keys[]  = {"master_key", "masterKey"};
    char*       json        = NULL;
    size_t      i;

    if (!input || !config) {
        return 1;
    }

    if (read_json_stream(input, &json) != 0) {
        return 1;
    }

    /* Parse JSON with cJSON */
    cJSON* root = cJSON_Parse(json);
    if (!root) {
        free(json);
        return 1;
    }

    /* port */
    {
        cJSON* port_item = cJSON_GetObjectItemCaseSensitive(root, "port");
        if (cJSON_IsNumber(port_item)) {
            config->port = (unsigned int)port_item->valueint;
        } else if (cJSON_IsString(port_item) && port_item->valuestring) {
            char* endptr = NULL;
            long  v      = strtol(port_item->valuestring, &endptr, 10);
            if (endptr != port_item->valuestring) {
                config->port = (unsigned int)v;
            }
        }
    }

    /* cors origin */
    for (i = 0; i < sizeof(cors_keys) / sizeof(cors_keys[0]); i++) {
        cJSON* item = cJSON_GetObjectItemCaseSensitive(root, cors_keys[i]);
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(config->cors_origin, sizeof(config->cors_origin), "%s", item->valuestring);
            break;
        }
    }

    /* data directory */
    for (i = 0; i < sizeof(data_keys) / sizeof(data_keys[0]); i++) {
        cJSON* item = cJSON_GetObjectItemCaseSensitive(root, data_keys[i]);
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(config->data_directory, sizeof(config->data_directory), "%s",
                     item->valuestring);
            break;
        }
    }

    /* temporary directory */
    for (i = 0; i < sizeof(temp_keys) / sizeof(temp_keys[0]); i++) {
        cJSON* item = cJSON_GetObjectItemCaseSensitive(root, temp_keys[i]);
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(config->temporary_directory, sizeof(config->temporary_directory), "%s",
                     item->valuestring);
            break;
        }
    }

    /* master key */
    for (i = 0; i < sizeof(key_keys) / sizeof(key_keys[0]); i++) {
        cJSON* item = cJSON_GetObjectItemCaseSensitive(root, key_keys[i]);
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(config->master_key, sizeof(config->master_key), "%s", item->valuestring);
            break;
        }
    }

    /* rate_limit */
    {
        cJSON* rl = cJSON_GetObjectItemCaseSensitive(root, "rate_limit");
        if (cJSON_IsObject(rl)) {
            cJSON* enabled = cJSON_GetObjectItemCaseSensitive(rl, "enabled");
            if (cJSON_IsBool(enabled))
                config->rate_limit_enabled = cJSON_IsTrue(enabled);

            config->rate_limit_api.bucket_count  = 1024;
            config->rate_limit_auth.bucket_count = 256;

            parse_rate_limit_zone(cJSON_GetObjectItemCaseSensitive(rl, "api"),
                                  &config->rate_limit_api);
            parse_rate_limit_zone(cJSON_GetObjectItemCaseSensitive(rl, "auth"),
                                  &config->rate_limit_auth);
        }
    }

    /* tls */
    {
        cJSON* tls = cJSON_GetObjectItemCaseSensitive(root, "tls");
        if (cJSON_IsObject(tls)) {
            cJSON* enabled = cJSON_GetObjectItemCaseSensitive(tls, "enabled");
            if (cJSON_IsBool(enabled))
                config->tls_enabled = cJSON_IsTrue(enabled);

            const char* cert_keys[] = {"certificate", "cert"};
            for (i = 0; i < sizeof(cert_keys) / sizeof(cert_keys[0]); i++) {
                cJSON* item = cJSON_GetObjectItemCaseSensitive(tls, cert_keys[i]);
                if (cJSON_IsString(item) && item->valuestring) {
                    snprintf(config->tls_cert_path, sizeof(config->tls_cert_path), "%s",
                             item->valuestring);
                    break;
                }
            }

            const char* key_keys[] = {"key"};
            for (i = 0; i < sizeof(key_keys) / sizeof(key_keys[0]); i++) {
                cJSON* item = cJSON_GetObjectItemCaseSensitive(tls, key_keys[i]);
                if (cJSON_IsString(item) && item->valuestring) {
                    snprintf(config->tls_key_path, sizeof(config->tls_key_path), "%s",
                             item->valuestring);
                    break;
                }
            }
        }
    }

    cJSON_Delete(root);
    free(json);
    return 0;
}

int cli_setup_parse(int argc, char* const argv[], CliConfig* config)
{
    const char* config_path = NULL;
    FILE*       config_file = NULL;
    int         i;

    if (!config) {
        return 1;
    }

    config->port = DEFAULT_PORT;
    snprintf(config->cors_origin, sizeof(config->cors_origin), "%s", DEFAULT_CORS);
    snprintf(config->data_directory, sizeof(config->data_directory), "%s", DEFAULT_DATA_DIRECTORY);
    snprintf(config->temporary_directory, sizeof(config->temporary_directory), "%s",
             DEFAULT_TEMP_DIRECTORY);
    config->master_key[0]      = '\0';
    config->rate_limit_enabled = 0;
    config->rate_limit_api     = (RateLimitConfig){
        .capacity = 100, .refill_rate = 10, .refill_interval_ms = 1000, .bucket_count = 1024};
    config->rate_limit_auth = (RateLimitConfig){
        .capacity = 5, .refill_rate = 1, .refill_interval_ms = 1000, .bucket_count = 256};
    config->tls_enabled      = 0;
    config->tls_cert_path[0] = '\0';
    config->tls_key_path[0]  = '\0';

    for (i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--config=", 9) == 0) {
            config_path = argv[i] + 9;
        } else if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --config\n");
                return 1;
            }

            config_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "Usage: %s [--config path]\n", argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Unknown argument: %s\nUsage: %s [--config path]\n", argv[i], argv[0]);
            return 1;
        }
    }

    if (config_path != NULL) {
        config_file = fopen(config_path, "r");
        if (!config_file) {
            fprintf(stderr, "Failed to open config file '%s'\n", config_path);
            return 1;
        }

        if (cli_setup_read_config(config_file, config) != 0) {
            fprintf(stderr, "Failed to read configuration from '%s'\n", config_path);
            fclose(config_file);
            return 1;
        }

        if (config->port == 0 || config->port > 65535) {
            fprintf(stderr, "Invalid port in config (must be 1-65535): %u\n", config->port);
            fclose(config_file);
            return 1;
        }

        if (config->tls_enabled) {
            if (config->tls_cert_path[0] == '\0') {
                fprintf(stderr, "TLS is enabled but no certificate path is configured\n");
                fclose(config_file);
                return 1;
            }
            if (config->tls_key_path[0] == '\0') {
                fprintf(stderr, "TLS is enabled but no key path is configured\n");
                fclose(config_file);
                return 1;
            }

            struct stat st;
            if (stat(config->tls_cert_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                fprintf(stderr, "TLS certificate file not found: %s\n", config->tls_cert_path);
                fclose(config_file);
                return 1;
            }
            if (stat(config->tls_key_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                fprintf(stderr, "TLS key file not found: %s\n", config->tls_key_path);
                fclose(config_file);
                return 1;
            }
        }

        fclose(config_file);
    }

    if (config->master_key[0] == '\0') {
        const char* env_key = getenv("X2S_MASTER_KEY");
        if (env_key) {
            snprintf(config->master_key, sizeof(config->master_key), "%s", env_key);
        }
    }

    if (config->master_key[0] != '\0') {
        size_t key_len = strlen(config->master_key);
        if (key_len != X2S_KEY_SIZE * 2) {
            fprintf(stderr, "error: master_key must be %d hex characters (got %zu)\n",
                    X2S_KEY_SIZE * 2, key_len);
            return 1;
        }
        unsigned char key_bytes[X2S_KEY_SIZE];
        if (!hex_to_bytes(config->master_key, key_bytes, X2S_KEY_SIZE)) {
            fprintf(stderr, "error: master_key contains invalid hex characters\n");
            return 1;
        }
        if (!encryption_init(key_bytes)) {
            fprintf(stderr, "error: failed to initialize encryption\n");
            return 1;
        }
    }

    return 0;
}