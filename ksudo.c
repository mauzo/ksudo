/*
 * ksudo(1) - limited remote command execution based on Kerberos principals
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#include <err.h>
#include <stdio.h>
#include <strings.h>
#include <sysexits.h>

#include <krb5.h>

#include "chk.h"
#include "asn1/ksudo.h"

krb5_context k5ctx;

void
usage ()
{
    errx(EX_USAGE, "Usage: ksudo server");
}

void
get_creds (const char *srvname, krb5_creds *cred)
{
    dKRBCHK;
    krb5_ccache     cc;
    krb5_principal  cli, srv;
    krb5_creds      mcred;

    debug("looking for [%s] in ccache...", srvname);

    KRBCHK(krb5_cc_default(k5ctx, &cc),
        "can't open ccache");

    KRBCHK(krb5_parse_name(k5ctx, srvname, &srv),
        "can't parse server name");

    debug("got server name");

    bzero(&mcred, sizeof mcred);
    mcred.server = srv;
    ke = krb5_cc_retrieve_cred(k5ctx, cc, 0, &mcred, cred);

    switch (ke) {
        case 0:
            debug("found ticket");
            if (cred->times.endtime > time(NULL) + 120) {
                debug("ticket is still valid");
                return;
            }
            debug("ticket has or is about to expire");
            KRBCHK(krb5_cc_remove_cred(k5ctx, cc, 0, cred),
                "can't remove stale creds from ccache");
            break;

        case KRB5_CC_NOTFOUND:
            break;

        default:
            KRBCHK(ke, "can't search ccache");
    }

    debug("doing an AS-REQ for [%s]...", srvname);

    KRBCHK(krb5_cc_get_principal(k5ctx, cc, &cli),
        "can't read client principal from ccache");

    KRBCHK(krb5_get_init_creds_password(k5ctx, cred, cli, NULL,
        krb5_prompter_posix, NULL, 0, srvname, NULL),
        "can't get ticket");

    KRBCHK(krb5_cc_store_cred(k5ctx, cc, cred),
        "can't store ticket in ccache");
}

int
main (int argc, char **argv)
{
    dKRBCHK;
    const char          *srv;
    krb5_creds          cred;

    if (argc != 2) usage();
    srv = argv[1];

    if (ke = krb5_init_context(&k5ctx))
        errx(EX_UNAVAILABLE, "can't create krb5 context");

    get_creds(srv, &cred);
}
