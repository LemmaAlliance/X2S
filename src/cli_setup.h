#ifndef CLI_SETUP_H
#define CLI_SETUP_H

#include <stdio.h>

typedef struct {
  unsigned int port;
  const char *cors_origin;
  FILE *config_file;
} CliConfig;

int cli_setup_parse(int argc, char *const argv[], CliConfig *config);

#endif
