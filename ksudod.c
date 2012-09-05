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
#include <unistd.h>

#include "ksudo.h"

char                *myname;
krb5_context        k5ctx;
krb5_keytab         k5kt;
krb5_principal      myprinc;

void            init            ();
void            ksudod          (int clisock);
void            read_cmd        (int clisock);
void            usage           ();

KSUDO_SOP(sop_read_cred);
KSUDO_SOP(sop_read_cmd);

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

KSUDO_SOP(sop_read_cred)
{
    dKSSOP(server);
    dKRBCHK;
    krb5_principal  cliprinc;
    char            *cliname;
    krb5_data       *aprep;

#define HEX(n) (int)((uchar*)pkt->data)[n]
    debug("AP-REQ pkt [%lx] length [%ld], start [%x%x%x%x%x%x%x%x%x]",
        (long)pkt, (long)pkt->length, 
        HEX(0), HEX(1), HEX(2), HEX(3), HEX(4), HEX(5),
        HEX(6), HEX(7), HEX(8));
#undef HEX

    KRBCHK(krb5_rd_req(k5ctx, &KssK5A(sess), pkt, myprinc, 
            k5kt, NULL, &data->tkt),
        "can't verify AP-REQ");

    KRBCHK(krb5_ticket_get_client(k5ctx, data->tkt, &cliprinc),
        "can't read client principal from ticket");
    KRBCHK(krb5_unparse_name(k5ctx, cliprinc, &cliname),
        "can't unparse client principal");

    debug("Got a ticket from [%s]", cliname);

    free(cliname);
    krb5_free_principal(k5ctx, cliprinc);

    New(aprep, 1);
    KRBCHK(krb5_mk_rep(k5ctx, KssK5A(sess), aprep),
        "can't build AP-REP");

    MbfPUSH(KssMBUF(sess), aprep);
    KssNEXT(sess, sop_read_cmd);
}

KSUDO_SOP(sop_read_cmd)
{
    dKSSOP(server);
    dRV;
    KSUDO_MSG   msg;
    KSUDO_CMD   *cmd;
    int         ncmd, i;
    size_t      len = 0;

    read_msg(sess, pkt, &msg); 
    if (msg.element != choice_KSUDO_MSG_cmd)
        errx(EX_PROTOCOL, "KSUDO-MSG is not a KSUDO-CMD");

    cmd     = &msg.u.cmd;
    ncmd    = cmd->cmd.len;
    for (i = 0; i < ncmd; i++)
        len += cmd->cmd.val[i].length;

    {
        size_t  tmpl;
        char    *tmp, *p;

        tmpl = cmd->user.length + 4 + len + ncmd * 2;
        New(tmp, tmpl);
        p = tmp;
        rv = snprintf(p, tmpl, "[%.*s] ",
            cmd->user.length, cmd->user.data);
        for (i = 0; i < ncmd; i++) {
            tmpl -= rv; p += rv;
            Assert(tmpl > 0);
            rv = snprintf(p, tmpl, "[%.*s]",
                cmd->cmd.val[i].length, cmd->cmd.val[i].data);
        }

        debug("KSUDO-CMD: %s", tmp);
        Free(tmp);
    }

    SYSCHK(data->pid = fork(), "fork failed");
    if (rv == 0) {
        char **cmdv, *cmds, *p;

        /* the ASN.1 structures are not null-terminated */
        NewZ(cmds, len + ncmd);
        NewZ(cmdv, ncmd + 1);

        p = cmds;
        for (i = 0; i < ncmd; i++) {
            size_t n = cmd->cmd.val[i].length;
            Copy(cmd->cmd.val[i].data, p, n);
            cmdv[i] = p;
            p += n + 1;
        }
        SYSCHK(execvp(cmdv[0], cmdv), "exec failed");
    }

    free_KSUDO_MSG(&msg);
}

void
create_listen_socks (char *host)
{
    dRV;
    int                 sck;
    ksudo_fddata_listen *ldata;

    if (!host) {
        New(host, MAXHOSTNAMELEN);
        SYSCHK(gethostname(host, MAXHOSTNAMELEN),
            "can't get my hostname");
    }

    sck = create_socket(host, AI_PASSIVE|AI_CANONNAME, &myname);
    SYSCHK(listen(sck, 10), "can't listen on socket");
    debug("got listen socket [%d] for [%s]", sck, myname);

    NewZ(ldata, 1);
    ldata->startop = sop_read_cred;
    ksf_open(sck, KSUDO_FD_READ, KSFt(listen), ldata);
}

void
usage ()
{
    errx(EX_USAGE, "Usage: ksudod hostname");
}

int
main (int argc, char **argv)
{
    if (argc > 2) usage();

    init();
    create_listen_socks(argc > 1 ? argv[1] : NULL);

    ioloop();

    krb5_free_context(k5ctx);
}
