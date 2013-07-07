#ifndef GUESTFS_HELPER_H
#define GUESTFS_HELPER_H

#ifdef HAVE_LIBGUESTFS
#include <guestfs.h>
#endif

#ifdef HAVE_LIBMAGIC
#include <magic.h>
#endif

int honeymon_guestfs_start(honeymon_t *honeymon, honeymon_clone_t *clone);
void honeymon_guestfs_stop(honeymon_clone_t *clone);

#endif
