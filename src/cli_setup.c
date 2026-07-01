#include "cli_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define DEFAULT_CORS "*"

int cli_setup_parse(int argc, char *const argv[], CliConfig *config) {
  int opt;

  if (!config) {
    return 1;
  }

  config->port = DEFAULT_PORT;
  config->cors_origin = DEFAULT_CORS;

  while ((opt = getopt(argc, argv, "p:c:")) != -1) {
    switch (opt) {
      case 'p':
        config->port = (unsigned int)atoi(optarg);
        break;
      case 'c':
        config->cors_origin = optarg;
        break;
      default:
        fprintf(stderr, "Usage: %s [-p port] [-c cors_origin]\n", argv[0]);
        return 1;
    }
  }

  return 0;
}

