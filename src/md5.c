#include <stdio.h>
#include <glib.h>
#include <openssl/md5.h>

#include "md5.h"

char *md5_sum(const char *file_path)
{
    FILE *inFile = fopen (file_path, "rb");
    if (inFile == NULL) {
        printf("MD5: Failed to open file at '%s'\n", file_path);
        return NULL;
    }

    MD5_CTX mdContext;
    MD5_Init (&mdContext);

    int bytes = 0;
    unsigned char data[4096];

    unsigned char c[MD5_DIGEST_LENGTH];

    while ((bytes = fread (data, 1, 4096, inFile)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);
    fclose (inFile);

    char *md5 = g_malloc0(snprintf(NULL, 0, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
      c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]) + 1);
    sprintf(md5, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
      c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

    return md5;

}
