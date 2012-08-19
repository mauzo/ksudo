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
buf_2data(ksudo_buf *buf, krb5_data *dat, size_t len)
{
    dKRBCHK;

    if (BufFILL(buf) < len) return -1;

    if (BufCONTIG(buf) >= len) {
        dat->data    = BufSTART(buf);
        dat->length   = len;
        return 0;
    }
    else {
        KRBCHK(krb5_data_alloc(dat, len),
            "can't allocate buffer");
        BufCPYOUT(buf, dat->data, len);
        return 1;
    }
}
