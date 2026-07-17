#ifndef OBJECT_IO_H
#define OBJECT_IO_H

/*
 * Low-level file I/O for object metadata and data blobs.
 *
 * Handles reading/writing individual object files, building file paths,
 * and reference-counting data blobs for deduplication cleanup.
 * All file operations use the format version vtable for forward compatibility.
 */

#include <stdio.h>
#include "core/object_types.h"

void free_metadata(Metadata* metadata);
void object_path(ObjectStore* store, const unsigned char id[OBJECT_ID_SIZE], char* out,
                 size_t out_len);
int  write_object_file(ObjectStore* store, Object* obj);
int  read_object_file(ObjectStore* store, const unsigned char id[OBJECT_ID_SIZE], Object* out);
void delete_metadata_file(ObjectStore* store, const unsigned char id[OBJECT_ID_SIZE]);
void delete_data_blob_file(ObjectStore* store, const unsigned char data_hash[OBJECT_ID_SIZE]);
int  count_data_blob_references(ObjectStore*        store,
                                const unsigned char target_data_hash[OBJECT_ID_SIZE],
                                const unsigned char current_meta_id[OBJECT_ID_SIZE]);
int  read_metadata_data_hash(const char* path, unsigned char hash[OBJECT_ID_SIZE]);

typedef struct
{
    FILE*          stream;
    unsigned char* buffer;
} DecryptedStream;

DecryptedStream decrypt_file_to_mem(FILE* f);
void            close_decrypted_stream(DecryptedStream* ds);
int             write_encrypted_body(FILE* f, const unsigned char* body, size_t body_len);

#endif
