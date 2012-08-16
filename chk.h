/*
 * Part of ksudo, a system to allow limited remote command execution
 * based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 */

#ifndef __chk_h__
#define __chk_h__

static inline void
debug(const char *msg, ...) { }
#define debug warnx

#define New(v, n) \
    if (!((v) = malloc(sizeof(*(v)) * (n)))) \
        err(EX_UNAVAILABLE, "malloc failed")

#define Renew(v, n) \
    if (!((v) = realloc((v), (n) * sizeof(*(v))))) \
        err(EX_UNAVAILABLE, "malloc failed")

#ifdef HAVE_FREE_OF_NULL
#  define Free free
#else
#  define Free(v) if (v) free(v)
#endif

#define Copy(f, t, n) \
    memcpy((t), (f), (n)*(sizeof(*(t))))

#define dKRBCHK krb5_error_code ke
#define KRBCHK(e, m) \
    if (ke = (e)) \
        krb5_err(k5ctx, EX_UNAVAILABLE, ke, (m))

#define dRV int rv
#define SYSCHK(e, m) \
    if ((rv = (e)) < 0) \
        err(1, (m))

#define RESCHK(e, m) \
    if ((rv = (e)) < 0) \
        errx(1, "%s: %s", (m), hstrerror(h_errno))

#define GAICHK(e, m) \
    if ((rv = (e))) \
        errx(1, "%s: %s", (m), (rv == EAI_SYSTEM \
            ? strerror(errno) : gai_strerror(rv))) 

#endif
