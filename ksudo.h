/*
 * This file is part of ksudo.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#ifndef __ksudo_h_not_asn1__
#define __ksudo_h_not_asn1__

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>

#include <krb5.h>

#include "config.h"
#include "compat.h"

#include "chk.h"
#include "asn1/ksudo.h"

#define KSUDO_SRV       "ksudo"
#define KSUDO_PORT      "8487"

/* I might implement variable-sized buffers later */
#define KSUDO_BUFSIZ    10240

extern krb5_context         k5ctx;
extern krb5_auth_context    k5auth;

typedef unsigned char       uchar;

/* A ring buffer. If end == BufSIZE, the buffer is full. */
typedef struct { 
    uchar   buf[KSUDO_BUFSIZ];
    size_t  start;
    size_t  end;
} ksudo_buf;

#define BufSIZE(b)  (KSUDO_BUFSIZ)

#define Buf_FULL(b, e)  ((e) == BufSIZE(b))
#define BufFULL(b)      Buf_FULL(b, (b)->end)
#define BufBUF(b)       ((b)->buf)
#define BufSTART(b)     (BufBUF(b) + (b)->start)
#define BufEND(b)       (BufFULL(b) ? BufSTART(b) : BufBUF(b) + (b)->end)

#define BufDIFF(b, s, e) \
    (Buf_FULL(b, e) ? BufSIZE(b) : \
        (s) > (e) ? (BufSIZE(b) - ((s) - (e))) : ((e) - (s)))
#define BufFILL(b) \
    (BufFULL(b) ? BufSIZE(b) : BufDIFF(b, (b)->start, (b)->end))
#define BufFREE(b)      (BufSIZE(b) - BufFILL(b))
#define BufCONTIG(b)    (BufSIZE(b) - (b)->start)
#define BufCFREE(b)     (BufSIZE(b) - (b)->end)

#define BufIX(b, p)     (BufBUF(b) + (p))
#define BufINC(b, p, n) \
    do { \
        Assert((p) >= 0 && (p) < BufSIZE(b)); \
        (p) += (n); \
        if ((p) > BufSIZE(b)) (p) -= BufSIZE(b); \
    } while (0)

#define BufEXTEND(b, n) \
    do { \
        BufINC(b, (b)->end, n); \
        if ((b)->end == (b)->start) (b)->end = BufSIZE(b); \
    } while (0)

#define BufCONSUME(b, n) \
    do { \
       if ((b)->end == BufSIZE(b)) (b)->end = (b)->start; \
       BufINC(b, (b)->start, n); \
    } while (0)

#define BufCPYIN(b, v, l) \
    do { \
        Assert((l) > BufFREE(b)); \
        if ((l) > BufCFREE(b)) { \
            Copy(BufEND(b), (v), BufCFREE(b)); \
            Copy(BufBUF(b), (v) + BufCFREE(b), (l) - BufCFREE(b)); \
        } \
        else \
            Copy(BufEND(b), (v), (l)); \
    } while (0)

#define BufCPYOUT(b, v, l) \
    do { \
        Assert((l) > BufFILL(b)); \
        if ((l) > BufCONTIG(b)) { \
            Copy((v), BufSTART(b), BufCONTIG(b)); \
            Copy((v) + BufCONTIG(b), BufBUF(b), (l) - BufCONTIG(b)); \
        } \
        else \
            Copy((v), BufSTART(b), (l)); \
    } while (0)

/* io.c */
void    read_packet     (int fd, krb5_data *packet);
void    write_packet    (int fd, krb5_data *packet);
void    read_msg        (int fd, KSUDO_MSG *msg);
void    write_msg       (int fd, KSUDO_MSG *msg);

/* sock.c */
int     create_socket   (const char *host, int flags, char **canon);

#endif
