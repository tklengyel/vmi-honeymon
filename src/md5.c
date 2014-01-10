#include <stdio.h>
#include <glib.h>
#include <openssl/md5.h>

#include "md5.h"

unsigned char *md5_sum(const char *file_path)
{
    unsigned char *c = g_malloc0(MD5_DIGEST_LENGTH+1);
    int i;
    FILE *inFile = fopen (file_path, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (inFile == NULL) {
        goto error;
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 4096, inFile)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);
    fclose (inFile);
    return c;

error:
    g_free(c);
    fclose (inFile);
    return NULL;
}
