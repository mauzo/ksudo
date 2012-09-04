/*-
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>

#include "ksudo.h"

int             nksfds      = 0;
ksudo_fd        *ksfds;
struct pollfd   *pollfds;

int
ksf_open (int fd, KSUDO_FD_MODE mode, ksudo_fdops *ops, void *data, 
            int hasbuf)
{
    dRV;
    int             i;
    ksudo_fd        *ksf;
    struct pollfd   *pf;
    int             fdflags;
    
    static const short mode_events[3] = {
        POLLIN,
        POLLOUT,
        POLLIN | POLLOUT
    };

    for (i = 0; i < nksfds; i++)
        if (KsfFD(i) == -1) break;

    if (i == nksfds) {
        int j;

        if (nksfds) {
            nksfds *= 2;
            Renew(ksfds, nksfds);
            Renew(pollfds, nksfds);
        }
        else {
            nksfds = 4;
            New(ksfds, nksfds);
            New(pollfds, nksfds);
        }

        for (j = i; j < nksfds; j++) {
            KsfPOLL(j).fd = -1;
        }
    }

    ksf = &KsfL(i);
    pf  = &KsfPOLL(i);

    bzero(pf, sizeof *pf);
    pf->fd          = fd;
    pf->events      = mode_events[mode];

    bzero(ksf, sizeof *ksf);
    ksf->read       = !!(pf->events & POLLIN);
    ksf->write      = !!(pf->events & POLLOUT);
    ksf->ops        = ops;
    ksf->data       = data;

    if (hasbuf) {
        if (KsfREAD(i))     NewBuf(ksf->rbuf);
        if (KsfWRITE(i))    NewBuf(ksf->wbuf);
    }

    SYSCHK(fdflags = fcntl(fd, F_GETFL, 0),
        "can't read fd flags");
    SYSCHK(fcntl(fd, F_SETFL, fdflags | O_NONBLOCK),
        "can't set fd nonblocking");

    return i;
}

void
ksf_close (int ix)
{
    ksudo_fd    *ksf;

    ksf = &KsfL(ix);
    Free(ksf->rbuf);
    Free(ksf->wbuf);
    Free(ksf->data);

    KsfPOLL(ix).fd  = -1;
}

void
ksf_read (int ix)
{
    dRV;
    int             fd      = KsfFD(ix);
    ksudo_buf       *buf    = KsfRBUF(ix);

    Assert(KsfREAD(ix));

    BufENSURE(buf, KSUDO_BUFSIZ);
    if (!BufFREE(buf)) return;

    rv = read(fd, BufEND(buf), BufFREE(buf));

    if (rv == EAGAIN) return;
    SYSCHK(rv, "read failed");

    BufEXTEND(buf, rv);
}

void
ksf_write (int ix)
{
    dRV;
    int             fd      = KsfFD(ix);
    ksudo_buf       *buf    = KsfWBUF(ix);

    Assert(KsfWRITE(ix));
    if (!BufFILL(buf)) return;

    rv = write(fd, BufSTART(buf), BufFILL(buf));

    if (rv == EAGAIN) return;
    SYSCHK(rv, "write failed");

    BufCONSUME(buf, rv);
}

void
ioloop ()
{
    dRV;
    int         i;

    while (1) {
        SYSCHK(poll(pollfds, nksfds, INFTIM),
            "poll failed");

        for (i = 0; i < nksfds; i++) {
            short   ev  = KsfPOLL(i).revents;

            if (ev & POLLIN)    KsfCALLOP(i, read_ready);
            if (ev & POLLOUT)   KsfCALLOP(i, write_ready);
        }
    }
}
