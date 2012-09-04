/*
 * ksudo(1) - limited remote command execution based on Kerberos principals
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 */

#include <sys/types.h>

#include <netdb.h>
#include <stdio.h>

#include "ksudo.h"

krb5_context        k5ctx;
krb5_auth_context   k5auth;

/* the client has just one session */
int             nsessions = 1;
ksudo_session   session;
ksudo_session   *sessions = &session;

char    *usr, **cmdv;
int     cmdc;

void    get_creds   (const char *host, krb5_creds *cred);
void    init        ();
void    send_cmd    ();
void    send_creds  (krb5_creds *cred);
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
    krb5_free_principal(k5ctx, srv);

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

    KRBCHK(krb5_cc_close(k5ctx, cc), "can't close ccache");

    free(srvname);
}

void
send_cmd ()
{
    dRV; dKRBCHK;
    KSUDO_MSG   msg, decode;
    KSUDO_CMD   *cmd;
    int         i;
    size_t      len, outlen;
    krb5_data   der, packet;

    msg.element         = choice_KSUDO_MSG_cmd;
    cmd = &msg.u.cmd;
    cmd->user.length    = strlen(usr);
    cmd->user.data      = strdup(usr);
    cmd->env.len        = 0;
    cmd->env.val        = NULL;
    cmd->cmd.len        = cmdc;

    New(cmd->cmd.val, cmdc);
    for (i = 0; i < cmdc; i++) {
        cmd->cmd.val[i].length  = strlen(cmdv[i]);
        cmd->cmd.val[i].data    = strdup(cmdv[i]);
    }

    write_msg(KssMBUF(0), &msg);
    free_KSUDO_MSG(&msg);
}

void
send_creds (krb5_creds *cred)
{
    dKRBCHK;
    krb5_data               *packet;

    New(packet, 1);
    KRBCHK(krb5_mk_req_extended(k5ctx, &k5auth, 0, NULL, cred, packet),
        "can't build AP-REQ");

#define HEX(x) (int)((uchar *)packet->data)[x]
    debug("AP-REQ length [%ld] start [%x%x%x%x%x%x%x%x%x]",
        (long)packet->length, HEX(0), HEX(1), HEX(2), HEX(3), HEX(4),
        HEX(5), HEX(6), HEX(7), HEX(8));
#undef HEX
    MbfPUSH(KssMBUF(0), packet);
}

KSUDO_SOP(sop_read_creds)
{
    dKRBCHK;
    krb5_ap_rep_enc_part    *ep;

#define HEX(x) (int)((uchar *)pkt->data)[x]
    debug("AP-REP length [%ld] start [%x%x%x%x%x%x%x%x%x]",
        (long)pkt->length, HEX(0), HEX(1), HEX(2), HEX(3), HEX(4),
        HEX(5), HEX(6), HEX(7), HEX(8));
#undef HEX

    KRBCHK(krb5_rd_rep(k5ctx, k5auth, pkt, &ep),
        "can't read AP-REP");
    krb5_free_ap_rep_enc_part(k5ctx, ep);

    debug("done AP exchange");

    send_cmd();
}

void
create_client_sock(const char *srv, char **canon)
{
    int sock;

    sock = create_socket(srv, AI_CANONNAME, canon);
    debug("create_socket: [%d]", sock);
    kss_init(0, sock, sop_read_creds);
}

void
usage ()
{
    errx(EX_USAGE, "Usage: ksudo server user cmd");
}

int
main (int argc, char **argv)
{
    dKRBCHK;
    char                *srv, *canon;
    int                 sock;
    krb5_creds          cred;

    if (argc < 4) usage();
    srv = argv[1];
    usr = argv[2];
    cmdv = argv + 3;
    cmdc = argc - 3;

    init();

    create_client_sock(srv, &canon);

    get_creds(canon, &cred);
    free(canon);

    send_creds(&cred);
    krb5_free_cred_contents(k5ctx, &cred);

    ioloop();

    krb5_free_context(k5ctx);
}
