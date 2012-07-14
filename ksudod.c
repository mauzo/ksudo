/*
 * Part of ksudo, a system to allow limited remote command execution
 * based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>
 * Released under the 2-clause BSD license.
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "ksudo.h"

char                *myname;
krb5_context        k5ctx;
krb5_auth_context   k5auth;
krb5_keytab         k5kt;
krb5_principal      myprinc;

void            init            ();
void            ksudod          (int clisock);
void            read_cmd        (int clisock);
krb5_ticket *   read_cred       (int clisock);
void            usage           ();

void
init ()
{
    dKRBCHK;

    ke = krb5_init_context(&k5ctx);
    if (ke)
        errx(EX_UNAVAILABLE, "can't create krb5 context");

    KRBCHK(krb5_kt_default(k5ctx, &k5kt),
        "can't open keytab");

    KRBCHK(krb5_sname_to_principal(k5ctx, myname, KSUDO_SRV,
            KRB5_NT_SRV_HST, &myprinc),
        "can't build server principal");
}

void
ksudod (int clisock)
{
    dKRBCHK;
    krb5_data       packet;
    krb5_ticket     *tkt;
    KSUDO_CMD       *cmd;

    KRBCHK(krb5_auth_con_init(k5ctx, &k5auth),
        "can't create auth context");

    tkt = read_cred(clisock);
    read_cmd(clisock);

    krb5_free_ticket(k5ctx, tkt);
    krb5_auth_con_free(k5ctx, k5auth);
}

void
read_cmd (int clisock)
{
    dRV;
    KSUDO_MSG   msg;
    KSUDO_CMD   *cmd;
    int         i;

    read_msg(clisock, &msg); 
    if (msg.element != choice_KSUDO_MSG_cmd)
        errx(EX_PROTOCOL, "KSUDO-MSG is not a KSUDO-CMD");

    cmd = &msg.u.cmd;

    debug("KSUDO-CMD: [%.*s]:", cmd->user.length, cmd->user.data);
    for (i = 0; i < cmd->cmd.len; i++) {
        debug("  [%.*s]", cmd->cmd.val[i].length, cmd->cmd.val[i].data);
    }

    free_KSUDO_MSG(&msg);
}

krb5_ticket *
read_cred (int clisock)
{
    dKRBCHK;
    krb5_data       packet;
    krb5_ticket     *tkt;
    krb5_principal  cliprinc;
    char            *cliname;

    read_packet(clisock, &packet);
    KRBCHK(krb5_rd_req(k5ctx, &k5auth, &packet, myprinc, k5kt, NULL, &tkt),
        "can't verify AP-REQ");
    krb5_data_free(&packet);

    KRBCHK(krb5_mk_rep(k5ctx, k5auth, &packet),
        "can't build AP-REP");
    send_packet(clisock, &packet);
    krb5_data_free(&packet);

    KRBCHK(krb5_ticket_get_client(k5ctx, tkt, &cliprinc),
        "can't read client principal from ticket");
    KRBCHK(krb5_unparse_name(k5ctx, cliprinc, &cliname),
        "can't unparse client principal");

    debug("Got a ticket from [%s]", cliname);

    free(cliname);
    krb5_free_principal(k5ctx, cliprinc);

    return tkt;
}

void
usage ()
{
    errx(EX_USAGE, "Usage: ksudod hostname");
}

int
main (int argc, char **argv)
{
    dRV;
    char    *host;
    int     srvsock, clisock;

    if (argc > 2) usage();
    if (argc > 1)
        host = argv[1];
    else {
        New(host, MAXHOSTNAMELEN);
        SYSCHK(gethostname(host, MAXHOSTNAMELEN),
            "can't get my hostname");
    }

    srvsock = create_socket(host, AI_PASSIVE|AI_CANONNAME, &myname);
    SYSCHK(listen(srvsock, 10), "can't listen on socket");
    debug("got listen socket [%d] for [%s]", srvsock, myname);

    init();

    while (1) {
        SYSCHK(clisock = accept(srvsock, NULL, 0),
            "can't accept connection");
        ksudod(clisock);
    }
}
