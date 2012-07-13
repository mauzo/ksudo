/*-
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <unistd.h>

#include "ksudo.h"

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
read_to_eof(int fd, krb5_data *buf)
{
    dRV; dKRBCHK;
    int cur, sz;

    cur = 0; sz = 1024;
    KRBCHK(krb5_data_alloc(buf, sz),
        "can't allocate buffer");

    while (rv = read(fd, buf->data + cur, sz - cur)) {
        SYSCHK(rv, "can't read stdin");
        cur += rv;
        if (sz - cur < 512) {
            sz += 1024;
            KRBCHK(krb5_data_realloc(buf, sz),
                "can't reallocate buffer");
        }
    }

    KRBCHK(krb5_data_realloc(buf, cur),
        "can't trim buffer");
}
