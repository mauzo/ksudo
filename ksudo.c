/*
 * ksudo(1) - limited remote command execution based on Kerberos principals
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#include <netdb.h>
#include <stdio.h>
#include <strings.h>

#include "ksudo.h"

krb5_context        k5ctx;
krb5_auth_context   k5auth;

void    get_creds   (const char *host, krb5_creds *cred);
void    init        ();
void    send_creds  (int sock, krb5_creds *cred);
void    usage       ();

void
init ()
{
    dKRBCHK;

    if (ke = krb5_init_context(&k5ctx))
        errx(EX_UNAVAILABLE, "can't create krb5 context");

    KRBCHK(krb5_auth_con_init(k5ctx, &k5auth),
        "can't create auth context");
}

void
get_creds (const char *host, krb5_creds *cred)
{
    dRV; dKRBCHK;
    char            *srvname;
    krb5_ccache     cc;
    krb5_principal  cli, srv;
    krb5_creds      mcred;

    SYSCHK(asprintf(&srvname, "%s/%s", KSUDO_SRV, host),
        "can't build server principal name");

    debug("looking for [%s] in ccache...", srvname);

    KRBCHK(krb5_cc_default(k5ctx, &cc),
        "can't open ccache");

    KRBCHK(krb5_parse_name(k5ctx, srvname, &srv),
        "can't parse server name");

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
        case KRB5_CC_END:
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

void
send_creds (int sock, krb5_creds *cred)
{
    dKRBCHK;
    krb5_data               packet;
    krb5_ap_rep_enc_part    *ep;

    KRBCHK(krb5_mk_req_extended(k5ctx, &k5auth, 0, NULL, cred, &packet),
        "can't build AP-REQ");
    send_packet(sock, &packet);
    krb5_data_free(&packet);

    read_packet(sock, &packet);
    KRBCHK(krb5_rd_rep(k5ctx, k5auth, &packet, &ep),
        "can't read AP-REP");
    krb5_data_free(&packet);
    krb5_free_ap_rep_enc_part(k5ctx, ep);

    debug("done AP exchange");
}

void
usage ()
{
    errx(EX_USAGE, "Usage: ksudo server");
}

int
main (int argc, char **argv)
{
    dKRBCHK;
    char                *srv, *canon;
    int                 sock;
    krb5_creds          cred;

    if (argc != 2) usage();
    srv = argv[1];

    init();

    sock = create_socket(srv, AI_CANONNAME, &canon);
    get_creds(canon, &cred);
    send_creds(sock, &cred);
}