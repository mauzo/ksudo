/*
 * This file is part of ksudo, a system for limited remote command
 * execution based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 * session.c: functions for ksudo_sessions.
 */

#include <sys/wait.h>

#include "ksudo.h"

void
kss_init (int sess, int fd, ksudo_sop start, void *data)
{
    dKRBCHK;
    ksudo_fddata_msg    *mdata;
    int                 ksf;
   
    NewZ(mdata, 1);
    mdata->session = sess;
    BufINIT(&mdata->rbuf);
   
    ksf = ksf_open(fd, KSUDO_FD_RDWR, KSFt(msg), mdata);
    KssMSGFDs(sess, ksf);
    KssNEXT(sess, start);
    KssL(sess).datafds  = NULL;
    KssL(sess).data     = data;
    Zero(KssL(sess).msgop, KSUDO_MSG_num);

    KRBCHK(krb5_auth_con_init(k5ctx, &KssK5A(sess)),
        "can't allocate auth context");
   
    debug("kss_init session [%d] mdata [0x%lx] ksf [%d]",
        sess, mdata, ksf);
}

void
kss_exit (int sess, int status)
{
    KSUDO_MSG       msg;
    KSUDO_EXIT      *exit;
    KSUDO_SIGNAL    *sig;
    
    AsnChoice(&msg, MSG, exit, exit);

    if (WIFEXITED(status)) {
        int *stat;

        AsnChoice(exit, EXIT, stat, status);
        *stat = WEXITSTATUS(status);
        debug("successful exit for [%d] [%d]", sess, *stat);
    }
    else if (WIFSIGNALED(status)) {
        KSUDO_SIGNAL *sig;

        AsnChoice(exit, EXIT, sig, signal);
        /* XXX need to map to KSUDO-SIGNAL enum */
        *sig = WTERMSIG(status);
        debug("signal exit for [%d] [%d]", sess, *sig);
    }
    else {
        void *v;

        AsnChoice(exit, EXIT, v, unknown);
        debug("unknown exit for [%d]");
    }

    write_msg(sess, &msg);
}

KSUDO_SOP(sop_dispatch_msg)
{
    KSUDO_MSG       msg;
    unsigned int    type;

    read_msg(sess, pkt, &msg);

    KssCALLOP(sess, msg);
    free_KSUDO_MSG(&msg);
}
