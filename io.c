/*-
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "ksudo.h"

int             nksfds      = 0;
ksudo_fd        *ksfds;
struct pollfd   *pollfds;

int
ksf_open (int fd, KSUDO_FD_MODE mode, KSF_TYPE type, void *data)
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
    ksf->ops        = type;
    ksf->data       = data;

    SYSCHK(fdflags = fcntl(fd, F_GETFL, 0),
        "can't read fd flags");
    SYSCHK(fcntl(fd, F_SETFL, fdflags | O_NONBLOCK),
        "can't set fd nonblocking");

    KsfCALLOP(i, open);
    debug("ksf_open fd [%d] ops [%lx] data [%lx]",
        fd, type, data);

    return i;
}

void
ksf_close (int ix)
{
    debug("ksf_close [%d]", ix);
    KsfCALLOP(ix, close);
    Free(KsfDATAv(ix));
    KsfPOLL(ix).fd  = -1;
}

void
ksf_read (int ix, ksudo_buf *buf)
{
    dRV;
    int             fd      = KsfFD(ix);

    BufENSURE(buf, KSUDO_BUFSIZ);
    if (!BufFREE(buf)) goto out;

    rv = read(fd, BufEND(buf), BufFREE(buf));
    debug("ksf_read [%d] [%lx] [%ld] -> [%d]", 
        fd, BufEND(buf), BufFREE(buf), rv);

    if (rv == -1 && errno == EAGAIN) return;
    SYSCHK(rv, "read failed");

    if (rv == 0) {
        debug("ksf_read: EOF on [%d]", ix);
        ksf_close(ix);
    }

    BufEXTEND(buf, rv);

  out:
    if (!BufFREE(buf)) KsfMODE_CLR(ix, KSFm_IN);
}

void
ksf_write (int ix, ksudo_buf *buf)
{
    dRV;
    int             fd      = KsfFD(ix);

    if (!BufFILL(buf)) goto out;

    rv = write(fd, BufSTART(buf), BufFILL(buf));
    debug("ksf_write [%d] [%lx] [%ld] -> [%d]", 
        fd, BufSTART(buf), BufFILL(buf), rv);

    if (rv == -1 && errno == EAGAIN) return;
    SYSCHK(rv, "write failed");

    BufCONSUME(buf, rv);

  out:
    if (!BufFILL(buf)) KsfMODE_CLR(ix, KSFm_OUT);
}

void
ioloop ()
{
    dRV;
    int i;

    setup_signals();

    while (1) {
        handle_signals();

        /* There is a race here: if a signal comes in between the
         * sigcaughtany check in handle_signals and the start of the
         * poll syscall, it will not interrupt the poll. AFAICS the only
         * solution is pselect(2), which means mucking about with signal
         * masks and select fd_sets.
         */

        rv = poll(pollfds, nksfds, INFTIM);
        if (rv < 0 && errno != EINTR) SYSCHK(rv, "poll failed");

        for (i = 0; i < nksfds; i++) {
            short   ev  = KsfPOLL(i).revents;
            KsfPOLL(i).revents = 0;

            if (ev & POLLIN)    KsfCALLOP(i, read);
            if (ev & POLLOUT)   KsfCALLOP(i, write);
        }
    }
}
