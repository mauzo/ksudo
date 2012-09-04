/*-
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 * session.c: manage sessions (mostly server-side)
 *
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>

#include "ksudo.h"

int             nsessions   = 0;
ksudo_session   *sessions   = NULL;

KSUDO_FDOP(listen_fd_read)
{
    dFDOP(listen);  dRV;
    int     cli, i;

    ckFDOP(listen);

    SYSCHK(cli = accept(KsfFD(ksf), NULL, NULL), 
        "can't accept connection");

    for (i = 0; i < nsessions; i++)
        if (!KssOK(i))
            break;

    if (i == nsessions) {
        int j;

        if (sessions) {
            nsessions *= 2;
            Renew(sessions, nsessions);
        }
        else {
            nsessions = 8; 
            New(sessions, 8);
        }

        for (j = i; j < nsessions; j++)
            /* don't use NULL, since that might not be a function
             * pointer type */
            sessions[j].state = KSSs_NONE;
    }

    kss_init(i, cli, data->startop);
}

ksudo_fdops ksudo_fdops_listen = {
    .read       = listen_fd_read,
    .write      = NULL,
    .unblock    = NULL
};
