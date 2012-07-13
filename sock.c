/*
 * This file is part of ksudo, a system to allow limited remote command
 * execution based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <string.h>
#include <sysexits.h>

#include "ksudo.h"

int
create_socket (const char *host, int flags, char **canon)
{
    dRV;
    struct addrinfo     hint, *res, *r;
    int                 sock;

    bzero(&hint, sizeof hint);
    hint.ai_family      = PF_UNSPEC;
    hint.ai_socktype    = SOCK_STREAM;
    hint.ai_protocol    = IPPROTO_TCP;
    hint.ai_flags       = flags;
    
    rv = getaddrinfo(host, KSUDO_SRV, &hint, &res);
    if (rv == EAI_NONAME) {
        debug("named service not found, using default port");
        hint.ai_flags |= AI_NUMERICSERV;
        rv = getaddrinfo(host, KSUDO_PORT, &hint, &res);
    }
    GAICHK(rv, "can't find my local address");

    for (r = res; r; r = r->ai_next) {
        char    host[NI_MAXHOST], port[NI_MAXSERV];

        GAICHK(getnameinfo(r->ai_addr, r->ai_addrlen,
            host, NI_MAXHOST, port, NI_MAXSERV,
            NI_NUMERICHOST | NI_NUMERICSERV),
            "can't get nameinfo");

        debug("got an addr: [%d] [%s]:[%s] [%s]",
            r->ai_family, host, port,
            (r->ai_canonname ? r->ai_canonname : "null"));
    }

    SYSCHK(sock = socket(res->ai_family, res->ai_socktype, 
            res->ai_protocol),
        "can't create socket");

    if (flags & AI_PASSIVE) {
        SYSCHK(bind(sock, res->ai_addr, res->ai_addrlen),
            "can't bind socket");
    }
    else {
        SYSCHK(connect(sock, res->ai_addr, res->ai_addrlen),
            "can't connect socket");
    }

    if (flags & AI_CANONNAME)
        *canon = strdup(res->ai_canonname);

    freeaddrinfo(res);

    return sock;
}

