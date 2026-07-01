#include "api_server.h"
#include "auth.h"
#include "cli_setup.h"
#include "obj_operations.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAIN_SLEEP_MS 100000

static volatile int running = 1;

static void handle_sigint(int sig) {
  (void)sig;
  running = 0;
}

int main(int argc, char *argv[]) {
  CliConfig config;

  if (cli_setup_parse(argc, argv, &config) != 0) {
    return 1;
  }

  unsigned int port = config.port;
  const char *cors_origin = config.cors_origin;

  printf("Welcome to X2S — eXtremely Simple Storage\n");

  ObjectStore *store = create_store(16, "./x2s_data");
  if (!store) {
    fprintf(stderr, "Failed to create object store\n");
    return 1;
  }

  UserStore *users = user_store_create(8);
  if (!users) {
    fprintf(stderr, "Failed to create user store\n");
    free_store(store);
    return 1;
  }

  user_store_load(users, store->store_path);

  SessionStore *sessions = session_store_create(16);
  if (!sessions) {
    fprintf(stderr, "Failed to create session store\n");
    user_store_free(users);
    free_store(store);
    return 1;
  }

  TokenStore tokens = {.users = users, .sessions = sessions};

  // Pass dynamic port configuration alongside the custom string assignment down safely
  ApiServer *api = api_server_start(port, cors_origin, store, &tokens);
  if (!api) {
    fprintf(stderr, "Failed to start API server on port %u\n", port);
    session_store_free(sessions);
    user_store_free(users);
    free_store(store);
    return 1;
  }

  printf("Listening on http://0.0.0.0:%u\n", port);
  printf("Allowed CORS Origin: %s\n", cors_origin);
  printf("  POST  /auth/register      register a new user\n");
  printf("  POST  /auth/login          authenticate and get a token\n");
  printf("  POST  /auth/logout         invalidate a token\n");
  printf("  POST  /objects             upload an object\n");
  printf("  GET   /objects             list owned objects\n");
  printf("  GET   /objects/<id>        retrieve an object\n");
  printf("  DELETE /objects/<id>       remove an object\n");
  printf("Press Ctrl-C to stop.\n\n");

  signal(SIGINT, handle_sigint);
  while (running){
    usleep(MAIN_SLEEP_MS);
    // sleep(1);
    check_token_expiry(sessions);
  }

  printf("\nShutting down...\n");
  api_server_stop(api);
  user_store_save(users, store->store_path);
  session_store_free(sessions);
  user_store_free(users);
  free_store(store);
  return 0;
}
