#ifndef MD5_H
#define MD5_H

#include <openssl/md5.h>

unsigned char *md5_sum(const char *file_path);

#endif
