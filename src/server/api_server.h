#ifndef API_SERVER_H
#define API_SERVER_H

#include "core/object_types.h"
#include "auth/auth.h"

/*
 * api_server.h — HTTP REST layer for X2S
 *
 * Routes
 * ------
 *   PUT    /objects              Upload an object. Body is raw data.
 *                                Optional headers:
 *                                  X-Category  : metadata category string
 *                                  X-Extension : file extension (no dot)
 *                                  X-Filename  : original filename
 *                                Returns 201 Created with JSON body:
 *                                  {"id":"<64-char hex>"}
 *
 *   GET    /objects/<hex-id>     Retrieve a stored object.
 *                                Returns 200 OK with raw data body.
 *                                Content-Type is derived from X-Extension
 *                                if present, otherwise application/octet-stream.
 *
 *   DELETE /objects/<hex-id>     Remove an object from the store.
 *                                Returns 204 No Content on success.
 *
 *   POST   /auth/register        Register a new user.
 *                                Body: username=<user>&password=<pass>
 *                                Returns 201 with {"token":"<64hex>","user_id":"<32hex>"}
 *
 *   POST   /auth/login           Authenticate and get a bearer token.
 *                                Body: username=<user>&password=<pass>
 *                                Returns 200 with {"token":"<64hex>","user_id":"<32hex>"}
 *
 *   POST   /auth/logout          Invalidate a bearer token.
 *                                Header: Authorization: Bearer <token>
 *                                Returns 204 No Content.
 *
 * Authentication:
 *   Existing object endpoints now also accept:
 *     Authorization: Bearer <64-hex-char-token>
 *   as an alternative to X-User-Id / X-Username headers.
 *
 * All error responses carry a JSON body: {"error":"<message>"}
 */

typedef struct ApiServer ApiServer;

/*
 * Create and start the HTTP server on the given port and with the specified CORS origin.
 */
ApiServer *api_server_start(unsigned int port, const char *cors_origin, const char *temporary_directory,
                            ObjectStore *store, TokenStore *tokens);

/*
 * Stop the server and free all resources.
 */
void api_server_stop(ApiServer *server);

#endif /* API_SERVER_H */