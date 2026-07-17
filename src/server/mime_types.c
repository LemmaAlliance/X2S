#include <string.h>
#include <strings.h>

const char* mime_for_extension(const char* ext)
{
    if (!ext)
        return "application/octet-stream";

    const struct
    {
        const char* ext;
        const char* mime;
    } table[] = {{"txt", "text/plain"},
                 {"html", "text/html"},
                 {"htm", "text/html"},
                 {"css", "text/css"},
                 {"js", "application/javascript"},
                 {"json", "application/json"},
                 {"xml", "application/xml"},
                 {"csv", "text/csv"},
                 {"png", "image/png"},
                 {"jpg", "image/jpeg"},
                 {"jpeg", "image/jpeg"},
                 {"gif", "image/gif"},
                 {"webp", "image/webp"},
                 {"svg", "image/svg+xml"},
                 {"pdf", "application/pdf"},
                 {"zip", "application/zip"},
                 {"gz", "application/gzip"},
                 {"mp3", "audio/mpeg"},
                 {"mp4", "video/mp4"},
                 {NULL, NULL}};

    for (int i = 0; table[i].ext; i++) {
        if (strcasecmp(ext, table[i].ext) == 0)
            return table[i].mime;
    }

    return "application/octet-stream";
}
