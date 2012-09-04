/*
 * This file is part of ksudo, a system for allowing remote command
 * execution based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 * msg.c: functions for reading and writing ASN.1 messages
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <unistd.h>

#include "ksudo.h"

static krb5_error_code
read_asn1_length (ksudo_buf *buf, krb5_data *pkt)
{
    uchar   *p, b;
    size_t  len, tlen, llen;

    if (BufFILL(buf) < 1)       return ASN1_OVERRUN;
    
    p = BufSTART(buf);

    /* skip tag */
    if (*p++ & 0x1f == 0x1f) {
        while (*p++ & 0x80) ;
        p++;
    }
    tlen = p - BufSTART(buf);
    debug("ASN.1: skipped [%d] bytes of tag", tlen);
        
    b = *p;

    if (b == 0xff || b == 0x80) return ASN1_BAD_LENGTH;

    if (b < 0x80) {
        llen = 1;
        len = b;
        goto done;
    }

    b &= 0x7f;
    llen = b + 1;
    debug("ASN.1: [%ld] length bytes", llen);
    if (BufFILL(buf) < tlen + llen) return ASN1_OVERRUN;

    p++;
    len = 0;

    /* A single initial zero byte is allowed to prevent the top bit from
     * being interpreted as a sign bit. I'm not actually certain this is
     * allowed for an ASN.1 length, but heimdal allows it...
     */
    if (b > 1 && *p == 0) {
        b--;
        p++;
    }

    if (b > sizeof(size_t))     return ASN1_BAD_LENGTH;

    while (b--) len = len * 256 + *(p++);

  done:
    len += tlen + llen;
    if (BufFILL(buf) < len)     return ASN1_OVERRUN;

    pkt->data   = BufSTART(buf);
    pkt->length = len;
    debug("ASN.1 pkt [%lx] data [%lx] len [%ld]",
        pkt, pkt->data, pkt->length);
    return 0;
}

int
write_msg (ksudo_msgbuf *buf, KSUDO_MSG *msg)
{
    dKRBCHK;
    size_t      len, outlen;
    krb5_data   der, *packet;

    if (!MbfAVAIL(buf)) return 0;

    len = length_KSUDO_MSG(msg);
    KRBCHK(krb5_data_alloc(&der, len), "can't allocate DER buffer");

    /* Because DER values are preceded by their lengths, Heimdal's
     * encode_ functions start at the end of the buffer and work
     * backwards.
     */
    KRBCHK(encode_KSUDO_MSG(der.data + len - 1, len, msg, &outlen),
        "can't DER-encode KSUDO-MSG");

    if (outlen != len)
        Panic("DER-encoding came out the wrong length");

    New(packet, 1);
    KRBCHK(krb5_mk_priv(k5ctx, k5auth, &der, packet, NULL),
        "can't encrypt KSUDO-MSG");
    krb5_data_free(&der);

    MbfPUSH(buf, packet);
    return 1;
}

int
read_msg (krb5_data *pkt, KSUDO_MSG *msg)
{
    dKRBCHK;
    size_t      len;
    krb5_data   der;

    KRBCHK(krb5_rd_priv(k5ctx, k5auth, pkt, &der, NULL),
        "can't decrypt KRB5-PRIV");

    KRBCHK(decode_KSUDO_MSG(der.data, der.length, msg, NULL),
        "can't decode KSUDO-MSG");
    krb5_data_free(&der);

    return 1;
}

KSUDO_FDOP(msg_fd_read)
{
    dFDOP(msg);  dKRBCHK;
    ksudo_buf   *buf;
    int         sess;
    krb5_data   pkt;

    ckFDOP(msg);
    buf     = &data->rbuf;
    sess    = data->session;

    Assert(KssOK(sess));

    ksf_read(ksf, buf);
    ke = read_asn1_length(buf, &pkt);
    if (ke == ASN1_OVERRUN) return;
    KRBCHK(ke, "can't read ASN.1 length");

    KssCALL(sess, &pkt);
    BufCONSUME(buf, pkt.length);
}

KSUDO_FDOP(msg_fd_write)
{
    dFDOP(msg);  dRV;
    ksudo_msgbuf    *b;
    struct iovec    iov[2];

    ckFDOP(msg);
    b   = &data->wbuf;

    if (!MbfLEFT(b)) return;

    iov[0].iov_base = MbfPTR(b);
    iov[0].iov_len  = MbfPTRl(b);
    iov[1].iov_base = MbfNEXTp(b);
    iov[1].iov_len  = MbfNEXTl(b);
    rv = writev(KsfFD(ksf), iov, MbfNEXT(b) ? 2 : 1);
    
    if (rv == EAGAIN) return;
    SYSCHK(rv, "can't write to msg fd");

    MbfCONSUME(b, rv);
}

ksudo_fdops ksudo_fdops_msg = {
    .read       = msg_fd_read,
    .write      = msg_fd_write
};
