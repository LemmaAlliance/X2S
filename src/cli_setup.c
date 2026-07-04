#include "cli_setup.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"

#define DEFAULT_PORT 8080
#define DEFAULT_CORS "*"
#define DEFAULT_DATA_DIRECTORY "./x2s_data"
#define DEFAULT_TEMP_DIRECTORY "/tmp/x2s"

/* Use cJSON for parsing instead of manual string extraction. */

static int read_json_stream(FILE *input, char **buffer_out) {
  char chunk[256];
  char *buffer = NULL;
  size_t length = 0;
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

      char *new_buffer = realloc(buffer, new_capacity);
      if (!new_buffer) {
        free(buffer);
        return 1;
      }

      buffer = new_buffer;
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
  *buffer_out = buffer;
  return 0;
}

int cli_setup_read_config(FILE *input, CliConfig *config) {
  const char *data_keys[] = {"data_directory", "data_dir", "dataDirectory"};
  const char *temp_keys[] = {"temporary_directory", "temporary_dir",
                              "temp_directory", "temp_dir",
                              "temporaryDirectory", "tempDirectory"};
  const char *cors_keys[] = {"cors_origin", "corsOrigin"};
  char *json = NULL;
  size_t i;

  if (!input || !config) {
    return 1;
  }

  if (read_json_stream(input, &json) != 0) {
    return 1;
  }

  /* Parse JSON with cJSON */
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    free(json);
    return 1;
  }

  /* port */
  {
    cJSON *port_item = cJSON_GetObjectItemCaseSensitive(root, "port");
    if (cJSON_IsNumber(port_item)) {
      config->port = (unsigned int)port_item->valueint;
    } else if (cJSON_IsString(port_item) && port_item->valuestring) {
      char *endptr = NULL;
      long v = strtol(port_item->valuestring, &endptr, 10);
      if (endptr != port_item->valuestring) {
        config->port = (unsigned int)v;
      }
    }
  }

  /* cors origin */
  for (i = 0; i < sizeof(cors_keys) / sizeof(cors_keys[0]); i++) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, cors_keys[i]);
    if (cJSON_IsString(item) && item->valuestring) {
      snprintf(config->cors_origin, sizeof(config->cors_origin), "%s", item->valuestring);
      break;
    }
  }

  /* data directory */
  for (i = 0; i < sizeof(data_keys) / sizeof(data_keys[0]); i++) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, data_keys[i]);
    if (cJSON_IsString(item) && item->valuestring) {
      snprintf(config->data_directory, sizeof(config->data_directory), "%s", item->valuestring);
      break;
    }
  }

  /* temporary directory */
  for (i = 0; i < sizeof(temp_keys) / sizeof(temp_keys[0]); i++) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, temp_keys[i]);
    if (cJSON_IsString(item) && item->valuestring) {
      snprintf(config->temporary_directory, sizeof(config->temporary_directory), "%s", item->valuestring);
      break;
    }
  }

  cJSON_Delete(root);
  free(json);
  return 0;
}

int cli_setup_parse(int argc, char *const argv[], CliConfig *config) {
  const char *config_path = NULL;
  FILE *config_file = NULL;
  int i;

  if (!config) {
    return 1;
  }

  config->port = DEFAULT_PORT;
  snprintf(config->cors_origin, sizeof(config->cors_origin), "%s", DEFAULT_CORS);
  snprintf(config->data_directory, sizeof(config->data_directory), "%s", DEFAULT_DATA_DIRECTORY);
  snprintf(config->temporary_directory, sizeof(config->temporary_directory), "%s", DEFAULT_TEMP_DIRECTORY);

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

    fclose(config_file);
  }

  return 0;
}