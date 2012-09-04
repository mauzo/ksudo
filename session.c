/*
 * This file is part of ksudo, a system for limited remote command
 * execution based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 * session.c: functions for ksudo_sessions.
 */

#include "ksudo.h"

void
kss_init (int sess, int fd, ksudo_sop start)
{
    ksudo_fddata_msg    *mdata;
    int                 ksf;
   
    NewZ(mdata, 1);
    mdata->session = sess;
    BufINIT(&mdata->rbuf);
   
    ksf = ksf_open(fd, KSUDO_FD_RDWR, KSFt(msg), mdata);
    KssMSGFD(sess, ksf);
    KssNEXT(sess, start);
    KssL(sess).datafds = NULL;
   
    debug("kss_init session [%d] mdata [0x%lx] ksf [%d]",
        sess, mdata, ksf);
}
