/*
 * This file is part of ksudo, a system for allowing limited remote
 * command execution based on Kerberos principals.
 *
 * exec.c: server-side process execution
 */

#include <stdio.h>
#include <unistd.h>

#include "ksudo.h"

#ifdef DEBUG
static void
do_exec_debug (KSUDO_CMD *cmd, int ncmd, size_t len)
{
    dRV;
    size_t  tmpl;
    char    *tmp, *p;
    int     i;

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
#endif

void
do_exec (KSUDO_CMD *cmd, ksudo_sdata_server *data)
{
    dRV;
    int     ncmd, i;
    size_t  len = 0, n;
    char    **cmdv, *cmds, *p;

    ncmd = cmd->cmd.len;
    for (i = 0; i < ncmd; i++) {
        len += cmd->cmd.val[i].length;
        debug("do_exec: arg [%d] len [%lu] total [%lu]",
            i, (unsigned long)cmd->cmd.val[i].length, (unsigned long)len);
    }

#ifdef DEBUG
    do_exec_debug(cmd, ncmd, len);
#endif

    SYSCHK(data->pid = fork(), "fork failed");
    if (rv != 0) return;

    debug("do_exec: done fork [%d]", (int)getpid());

    /* the ASN.1 structures are not null-terminated */
    NewZ(cmds, len + ncmd);
    NewZ(cmdv, ncmd + 1);

    p = cmds;
    for (i = 0; i < ncmd; i++) {
        n = cmd->cmd.val[i].length;
        Copy(cmd->cmd.val[i].data, p, n);
        cmdv[i] = p;
        p += n + 1;
    }

    debug("do_exec: calling exec");
    SYSCHK(execvp(cmdv[0], cmdv), "exec failed");
}
