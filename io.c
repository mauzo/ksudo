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

void
send_packet (int sck, const krb5_data *pkt)
{
    dRV;
    uint32_t nlen;
    struct iovec iov[2];
    
    nlen = htonl(pkt->length);
    
    iov[0].iov_base = (void *)&nlen;
    iov[0].iov_len  = 4;            /* don't use sizeof, just in case */
    iov[1].iov_base = pkt->data;
    iov[1].iov_len  = pkt->length;

    SYSCHK(writev(sck, iov, 2), "write failed");
    if (rv == pkt->length + 4) {
        debug("sent packet of length %d", pkt->length);
        return;
    }
    errx(1, "short write: %d of %ld bytes", rv, (long)pkt->length);
}

void
read_packet (int sck, krb5_data *pkt)
{
    dRV; dKRBCHK;
    uint32_t    nlen, len;

    SYSCHK(read(sck, &nlen, 4), "can't read packet length");
    if (rv != 4)
        errx(1, "short read: %u", rv);

    len = ntohl(nlen);

    KRBCHK(krb5_data_alloc(pkt, len), "can't allocate packet");

    SYSCHK(read(sck, pkt->data, pkt->length), "can't read packet");

    if (rv != pkt->length)
        errx(1, "short read: %d of %ld bytes", rv, (long)pkt->length);

    debug("read of %d", rv);
}

void
send_msg (int sock, KSUDO_MSG *msg)
{
    dKRBCHK;
    size_t      len, outlen;
    krb5_data   der, packet;

    len = length_KSUDO_MSG(msg);
    KRBCHK(krb5_data_alloc(&der, len),
        "can't allocate DER buffer");

    /* Because DER values are preceded by their lengths, Heimdal's
     * encode_ functions start at the end of the buffer and work
     * backwards.
     */
    KRBCHK(encode_KSUDO_MSG(der.data + len - 1, len, msg, &outlen),
        "can't DER-encode KSUDO-MSG");
    free_KSUDO_MSG(msg);

    if (outlen != len)
        errx(EX_SOFTWARE, "DER-encoding came out the wrong length");

    KRBCHK(krb5_mk_priv(k5ctx, k5auth, &der, &packet, NULL),
        "can't encrypt KSUDO-MSG");
    krb5_data_free(&der);

    send_packet(sock, &packet);
    krb5_data_free(&packet);
}

void
read_msg (int sock, KSUDO_MSG *msg)
{
    dKRBCHK;
    krb5_data   packet, der;

    read_packet(sock, &packet);

    KRBCHK(krb5_rd_priv(k5ctx, k5auth, &packet, &der, NULL),
        "can't decrypt KSUDO-MSG");
    krb5_data_free(&packet);

    KRBCHK(decode_KSUDO_MSG(der.data, der.length, msg, NULL),
        "can't decode KSUDO-MSG");
    krb5_data_free(&der);
}

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
