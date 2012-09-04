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

#define NOOP (void)0

#ifdef DEBUG
#  define debug warnx
#else
static inline void
debug(const char *msg, ...) { }
#endif

#define Panic(m) errx(EX_SOFTWARE, "panic: %s", (m))

/* This is an ordinary assert() which returns void. AssertX below is
 * more useful in some circumstances, but only works with expressions
 * which can be passed to typeof(). Since this does not include
 * bitfields we need an alternative.
 */
#ifdef DEBUG
#  define Assert(e) \
    do { \
        if (!(e)) \
            errx(EX_SOFTWARE, \
                "Assertion failed: %s at %s line %u", \
                #e, __FILE__, __LINE__); \
    } while (0)
#else
#  define Assert(e) NOOP
#endif

/* This is an assert() which returns the value asserted. To implement
 * this we need GCC's block-expressions, so don't bother with it if we
 * don't have them.
 */
#if defined(DEBUG) && defined(HAVE_BLOCK_EXPR)
#  define AssertX(e) \
    ({ \
        typeof(e) __tmpe = (e); \
        if (!__tmpe) \
            errx(EX_SOFTWARE, \
                "Assertion failed: %s at %s line %u", \
                #e, __FILE__, __LINE__); \
        __tmpe; \
    })
#  define AssertXX(a, v) ({ Assert(a); (v); })
#else
#  define AssertX(e)        (e)
#  define AssertXX(a, v)    (v)
#endif

#ifdef DEBUG_MEM
#  define mem_debug debug
#else
#  define mem_debug(m, ...) NOOP
#endif

#define New(v, n) \
    do { \
        if (!((v) = malloc(sizeof(*(v)) * (n)))) \
            err(EX_UNAVAILABLE, "malloc failed"); \
        mem_debug("New [%lx]", (v)); \
    } while (0)

#define Renew(v, n) \
    do { \
        mem_debug("Renew [%lx]", (v)); \
        if (!((v) = realloc((v), (n) * sizeof(*(v))))) \
            err(EX_UNAVAILABLE, "malloc failed"); \
        mem_debug("  -> [%lx]", (v)); \
    } while (0)

#ifdef DEBUG_MEM
#  define Free(v) \
    do { mem_debug("Free [%lx]", (v)); if (v) free(v); } while (0)
#else
#  ifdef HAVE_FREE_OF_NULL
#    define Free free
#  else
#    define Free(v) if (v) free(v)
#  endif
#endif

#define Copy(f, t, n) \
    memcpy((t), (f), (n)*(sizeof(*(t))))

#define Zero(v, n) \
    memset((v), 0, (n)*sizeof(*(v)))

#define NewZ(v, n) do { New((v), (n)); Zero((v), (n)); } while (0)

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
