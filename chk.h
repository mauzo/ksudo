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
        err(1, "malloc failed")

#define dKRBCHK krb5_error_code ke
#define KRBCHK(e, m) \
    if (ke = (e)) \
        krb5_err(k5ctx, EX_UNAVAILABLE, ke, (m))

#define dSYSCHK int rv
#define SYSCHK(e, m) \
    if ((rv = (e)) < 0) \
        err(1, (m))

#define dRESCHK int h_rv
#define RESCHK(e, m) \
    if ((h_rv = (e)) < 0) \
        errx(1, "%s: %s", (m), hstrerror(h_errno))

#endif
