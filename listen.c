/*-
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 * session.c: manage sessions (mostly server-side)
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include "ksudo.h"

int             nsessions   = 0;
ksudo_session   *sessions   = NULL;

KSUDO_FDOP(listen_fd_read)
{
    dFDOP(listen);  dRV;
    int     cli, i;
    struct sockaddr_storage raddr;
    struct sockaddr         *raddrp;
    socklen_t               raddrlen;
    char    host[NI_MAXHOST], srv[NI_MAXSERV];

    ckFDOP(listen);

    raddrp      = (struct sockaddr *)&raddr;
    raddrlen    = sizeof(raddr);
    SYSCHK(cli = accept(KsfFD(ksf), raddrp, &raddrlen), 
        "can't accept connection");

    GAICHK(getnameinfo(raddrp, raddrlen, host, sizeof(host),
            srv, sizeof(srv), 0),
        "can't resolve client address");
    debug("accepted connection from [%s]:[%s]", host, srv);

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

    KssINIT(i, server, cli, data->startop);
}

ksudo_fdops ksudo_fdops_listen = {
    .read       = listen_fd_read,
    .write      = NULL,
    .unblock    = NULL
};
