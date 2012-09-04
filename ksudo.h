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
#include <poll.h>
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

/* This is a buffer which holds at least KSUDO_BUFSIZ. If necessary the
 * active portion gets moved back to the beginning, since the krb5
 * functions require their buffers to be contiguous.
 */
typedef struct { 
    uchar   buf[2*KSUDO_BUFSIZ];
    uchar   *start;
    uchar   *end;
} ksudo_buf;

#define BufSIZE(b)      (2*KSUDO_BUFSIZ)

#define BufBUF(b)       ((b)->buf)
#define BufSTART(b)     ((b)->start)
#define BufEND(b)       ((b)->end)
#define BufBUFEND(b)    (BufBUF(b) + BufSIZE(b))

#define BufFILL(b)      (BufEND(b) - BufSTART(b))
#define BufFREE(b)      (BufBUFEND(b) - BufEND(b))

#define NewBuf(b) \
    do { \
        New(b, 1); \
        (b)->start = (b)->end = BufBUF(b); \
    } while (0)

/* Attempt to ensure BufFREE is at least n. This may not succeed, so be
 * sure to check BufFREE afterwards.
 */
#define BufENSURE(b, n) \
    do { \
        Assert((n) <= KSUDO_BUFSIZ); \
        if (BufFREE(b) < (n)) { \
            Copy(BufSTART(b), BufBUF(b), BufFILL(b)); \
            (b)->end = BufBUF(b) + BufFILL(b); \
            (b)->start = BufBUF(b); \
        } \
    } while (0)

/* Shift the end of the buffer forwards. This should be called *after*
 * populating the newly-valid region of the buffer.
 */
#define BufEXTEND(b, n) \
    do { \
        Assert((n) <= BufFREE(b)); \
        (b)->end += (n); \
    } while (0)

/* Shift the beginning of the buffer forwards. If the buffer ends up
 * empty, take advantage of the situation to reset both pointers back to
 * the beginning.
 */
#define BufCONSUME(b, n) \
    do { \
        Assert((n) <= BufFILL(b)); \
        (b)->start += (n); \
        if (BufFILL(b) == 0) { \
            (b)->start  = BufBUF(b); \
            (b)->end    = BufBUF(b); \
        } \
    } while (0)

typedef struct {
    krb5_data   *cur;
    void        *ptr;
    krb5_data   *next;
} ksudo_msgbuf;

#define MbfCUR(b)       ((b)->cur)
#define MbfCURp(b)      (MbfCUR(b) ? MbfCUR(b)->data : NULL)
#define MbfCURl(b)      (MbfCUR(b) ? MbfCUR(b)->length : 0)

#define MbfPTR(b)       ((b)->ptr)
#define MbfPTRl(b)      (MbfCURl(b) - (MbfPTR(b) - MbfCURp(b)))

#define MbfNEXT(b)      ((b)->next)
#define MbfNEXTp(b)     (MbfNEXT(b) ? MbfNEXT(b)->data : NULL)
#define MbfNEXTl(b)     (MbfNEXT(b) ? MbfNEXT(b)->length : 0)
#define MbfLEFT(b)      (MbfPTRl(b) + MbfNEXTl(b))

#define MbfAVAIL(b)     (!MbfNEXT(b))

#define NewMsgBuf(b)    NewZ(b, 1)

#define MbfPUSH(b, d) \
    do { \
        Assert(MbfAVAIL(b)); \
        if (MbfCUR(b)) \
            (b)->next = (d); \
        else { \
            (b)->cur = (d); \
            (b)->ptr = (d)->data; \
        } \
    } while (0)

#define MbfCONSUME(b, n) \
    do { \
        Assert(MbfCUR(b)); \
        if ((n) < MbfPTRl(b)) \
            (b)->ptr += (n); \
        else { \
            Assert(MbfLEFT(b) <= (n)); \
            Assert(MbfNEXT(b) || (n) == MbfPTRl(b)); \
            \
            (b)->ptr = MbfNEXTp(b) + ((n) - MbfPTRl(b)); \
            krb5_free_data(k5ctx, MbfCUR(b)); \
            (b)->cur = MbfNEXT(b); \
            (b)->next = NULL; \
        } \
    } while (0)

typedef struct {
    void    (*read_ready)   (int, void *);
    void    (*write_ready)  (int, void *);
    int     (*try_unblock)  (int, void *);
} ksudo_fdops;

typedef struct {
    unsigned    read        : 1;
    unsigned    write       : 1;
    unsigned    blocking    : 1;
    unsigned    wndsent     : 1;

    ksudo_fdops     *ops;
    void            *data;

    ksudo_buf       *rbuf;
    ksudo_buf       *wbuf;
    /* the ix of the ksfd we are blocked on */
    int             blocked;
} ksudo_fd;

#define KsfL(f)     (ksfds[(f)])

#define KsfREAD(f)  (KsfL(f).read)
#define KsfWRITE(f) (KsfL(f).write)

#define KsfHASOP(f, o)  (KsfL(f).ops && KsfL(f).ops->o)
/* This assumes ops are always called in void context. If that changes
 * this will need to change to a (?:) expression.
 */
#define KsfCALLOP(f, o) \
    if (KsfHASOP(f, o)) KsfL(f).ops->o((f), KsfL(f).data)

#define KsfRBUF(f)  AssertX(KsfL(f).rbuf)
#define KsfWBUF(f)  AssertX(KsfL(f).wbuf)

#define KsfPOLL(f)  (pollfds[(f)])
#define KsfFD(f)    (KsfPOLL(f).fd)

typedef struct {
    int     session;
} ksudo_fddata_msg;

typedef struct {
    int     session;
    int     fd;
    /* wbuf->start last time we sent a window update */
    uchar   *lastwnd;
    /* the maximum size of our next packet */
    size_t  nextwnd;
} ksudo_fddata_data;

extern int              nksfds;
extern ksudo_fd         *ksfds;
extern struct pollfd    *pollfds;

/* io.c */
int     ksf_open        (int fd, KSUDO_FD_MODE mode, ksudo_fdops *ops, 
                            void *data, int hasbuf);
void    ksf_close       (int ix);
void    ksf_read        (int ix);
void    ksf_write       (int ix);
void    ioloop          ();

/* msg.c */
int     read_msg        (krb5_data *pkt, KSUDO_MSG *msg);
int     write_msg       (ksudo_msgbuf *buf, KSUDO_MSG *msg);

/* sock.c */
int     create_socket   (const char *host, int flags, char **canon);

#endif
