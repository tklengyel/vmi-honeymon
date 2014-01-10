#include <stdio.h>
#include <glib.h>
#include <openssl/md5.h>

#include "md5.h"

unsigned char *md5_sum(const char *file_path)
{
    FILE *inFile = fopen (file_path, "rb");
    if (inFile == NULL) {
        return NULL;
    }

    MD5_CTX mdContext;
    MD5_Init (&mdContext);

    int bytes;
    unsigned char data[4096];

    unsigned char *c = g_malloc0(MD5_DIGEST_LENGTH+1);

    while ((bytes = fread (data, 1, 4096, inFile)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);

    fclose (inFile);
    return c;

}
