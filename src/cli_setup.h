#ifndef CLI_SETUP_H
#define CLI_SETUP_H

#include <stdio.h>

typedef struct {
  unsigned int port;
  char cors_origin[4096];
  char data_directory[4096];
  char temporary_directory[4096];
} CliConfig;

int cli_setup_parse(int argc, char *const argv[], CliConfig *config);
int cli_setup_read_config(FILE *input, CliConfig *config);

#endif
