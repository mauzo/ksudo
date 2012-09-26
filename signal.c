/*
 * This file is part of ksudo, a system for allowing limited remote
 * command execution based on Kerberos principals.
 *
 * Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 *
 * signal.c: signal handlers
 */

#include <signal.h>

#include "ksudo.h"

static volatile sig_atomic_t sigcaughtany = 0;

static void 
sig_handler (int sig)
{
    int i;

    for (i = 0; i < nsigs; i++) {
        if (sigwant[i] == sig) {
            sigcaught[i] = 1;
            sigcaughtany = 1;
            break;
        }
    }
}

void
setup_signals ()
{
    dRV;
    int                 i;
    struct sigaction    sa;
    
    sigemptyset(&sa.sa_mask);
    sa.sa_handler   = sig_handler;

    for (i = 0; i < nsigs; i++) {
        int sig = sigwant[i];

        sa.sa_flags = (sig == SIGCHLD ? SA_NOCLDSTOP : 0);
        SYSCHK(sigaction(sig, &sa, NULL),
            "can't set signal handler");
    }
}

void
handle_signals ()
{
    int     i;

    if (!sigcaughtany) return;
    sigcaughtany = 0;

    for (i = 0; i < nsigs; i++) {
        if (sigcaught[i])
            (sigops[i])();
    }
}
