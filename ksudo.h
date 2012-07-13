/*
 * This file is part of ksudo.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#ifndef __ksudo_h__
#define __ksudo_h__

#include <err.h>
#include <errno.h>
#include <sysexits.h>

#include <krb5.h>

#include "chk.h"
#include "asn1/ksudo.h"

#define KSUDO_SRV   "ksudo"
#define KSUDO_PORT  "8487"

extern krb5_context     k5ctx;

/* io.c */
void    read_packet     (int fd, krb5_data *packet);
void    write_packet    (int fd, krb5_data *packet);

/* sock.c */
int     create_socket   (const char *host, int flags, char **canon);

#endif
