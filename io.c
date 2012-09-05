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

static sig_atomic_t sigchld = 0;

static void 
sigchld_handler (int sig)
{
    sigchld = 1;
}

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
    if (!BufFREE(buf)) return;

    rv = read(fd, BufEND(buf), BufFREE(buf));
    debug("ksf_read [%d] [%lx] [%ld] -> [%d]", 
        fd, BufEND(buf), BufFREE(buf), rv);

    if (rv == EAGAIN) return;
    SYSCHK(rv, "read failed");

    if (rv == 0) {
        debug("ksf_read: EOF on [%d]", ix);
        ksf_close(ix);
    }

    BufEXTEND(buf, rv);
}

void
ksf_write (int ix, ksudo_buf *buf)
{
    dRV;
    int             fd      = KsfFD(ix);

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
    int                 i;
    struct sigaction    sa;
    
    sa.sa_handler   = sigchld_handler;
    sa.sa_flags     = SA_NOCLDSTOP;
    SYSCHK(sigaction(SIGCHLD, &sa, NULL),
        "can't set SIGCHLD handler");

    while (1) {
        SYSCHK(poll(pollfds, nksfds, INFTIM),
            "poll failed");

        if (sigchld) {
            /* reset before performing the wait, in case a signal comes
             * in just after we reset */
            sigchld = 0;
            while (1) {
                int     stat;
                pid_t   kid;

                kid = waitpid(-1, &stat, WNOHANG);
                if (kid == 0)               break;
                if (kid < 0) {
                    if (errno == ECHILD)    break;
                    SYSCHK(kid, "wait failed");
                }

                debug("child exitted: pid [%ld] stat [%d]",
                    (long)kid, stat);
            }
        }

        for (i = 0; i < nksfds; i++) {
            short   ev  = KsfPOLL(i).revents;

            if (ev & POLLIN)    KsfCALLOP(i, read);
            if (ev & POLLOUT)   KsfCALLOP(i, write);
        }
    }
}
