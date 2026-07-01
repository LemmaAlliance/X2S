#include "cli_setup.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define DEFAULT_CORS "*"
#define DEFAULT_DATA_DIRECTORY "./x2s_data"
#define DEFAULT_TEMP_DIRECTORY "/tmp/x2s"

static int extract_string_value_for_key(const char *json, const char *key,
                                        char *value, size_t value_capacity) {
  const char *match;
  const char *cursor;
  const char *start;
  const char *end;
  size_t len;

  if (!json || !key || !value || value_capacity == 0) {
    return 1;
  }

  match = strstr(json, key);
  while (match) {
    cursor = strchr(match + strlen(key), ':');
    if (cursor) {
      cursor++;
      while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
        cursor++;
      }

      if (*cursor == '"') {
        start = cursor + 1;
        end = start;
        while (*end != '\0' && (*end != '"' || (end > start && end[-1] == '\\'))) {
          end++;
        }

        if (*end == '"') {
          len = (size_t)(end - start);
          if (len + 1 > value_capacity) {
            return 1;
          }

          memcpy(value, start, len);
          value[len] = '\0';
          return 0;
        }
      }
    }

    match = strstr(match + strlen(key), key);
  }

  return 1;
}

static int extract_int_value_for_key(const char *json, const char *key, int *value_out) {
  const char *match;
  const char *cursor;
  char *endptr;
  long value;

  if (!json || !key || !value_out) {
    return 1;
  }

  match = strstr(json, key);
  while (match) {
    cursor = strchr(match + strlen(key), ':');
    if (cursor) {
      cursor++;
      while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
        cursor++;
      }

      if (*cursor != '\0' && *cursor != '"') {
        errno = 0;
        value = strtol(cursor, &endptr, 10);
        if (errno == 0 && endptr != cursor) {
          *value_out = (int)value;
          return 0;
        }
      }
    }

    match = strstr(match + strlen(key), key);
  }

  return 1;
}

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
  char value[4096];
  int parsed_port = 0;
  size_t i;

  if (!input || !config) {
    return 1;
  }

  if (read_json_stream(input, &json) != 0) {
    return 1;
  }

  if (extract_int_value_for_key(json, "port", &parsed_port) == 0) {
    config->port = (unsigned int)parsed_port;
  }

  for (i = 0; i < sizeof(cors_keys) / sizeof(cors_keys[0]); i++) {
    if (extract_string_value_for_key(json, cors_keys[i], value, sizeof(value)) == 0) {
      snprintf(config->cors_origin, sizeof(config->cors_origin), "%s", value);
      break;
    }
  }

  for (i = 0; i < sizeof(data_keys) / sizeof(data_keys[0]); i++) {
    if (extract_string_value_for_key(json, data_keys[i], value, sizeof(value)) == 0) {
      snprintf(config->data_directory, sizeof(config->data_directory), "%s", value);
      break;
    }
  }

  for (i = 0; i < sizeof(temp_keys) / sizeof(temp_keys[0]); i++) {
    if (extract_string_value_for_key(json, temp_keys[i], value, sizeof(value)) == 0) {
      snprintf(config->temporary_directory, sizeof(config->temporary_directory), "%s", value);
      break;
    }
  }

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

    fclose(config_file);
  }

  return 0;
}