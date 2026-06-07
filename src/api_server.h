#ifndef API_SERVER_H
#define API_SERVER_H

#include "obj_structs.h"

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
 * All error responses carry a JSON body: {"error":"<message>"}
 */

typedef struct ApiServer ApiServer;

/*
 * Create and start the HTTP server on the given port.
 * The server takes a reference to an existing ObjectStore; it does not
 * own the store and will not free it.
 *
 * Returns NULL on failure (port in use, memory error, etc.).
 */
ApiServer *api_server_start(unsigned int port, ObjectStore *store);

/*
 * Stop the server and free all resources. Blocks until the internal
 * polling thread has shut down. Does not free the ObjectStore.
 */
void api_server_stop(ApiServer *server);

#endif /* API_SERVER_H */