# 
# Makefile for ksudo, a system to allow limited remote command execution
# based on Kerberos principals.
#
# Copyright 2012 Ben Morrow <ben@morrow.me.uk>
# Released under the 2-clause BSD licence.
#

CFLAGS=		-g

CFLAGS_krb5!=	krb5-config --cflags krb5
CFLAGS+= 	-I. ${CFLAGS_krb5}

LIBS_krb5!=	krb5-config --libs krb5
LIBS+=		${LIBS_krb5}

PROGS=		ksudo ksudod
OBJS_ksudo=	ksudo.o asn1/asn1.o io.o sock.o
OBJS_ksudod=	ksudod.o asn1/asn1.o io.o sock.o

.for p in ${PROGS}
OBJS+=		${OBJS_${p}}
.endfor

all: ${PROGS}

.for p in ${PROGS}
${p}: ${OBJS_${p}}
	${CC} -o ${.TARGET} ${LDFLAGS} ${.ALLSRC} ${LIBS}

.endfor

.for o in ${OBJS}
${o}: config.h compat.h ksudo.h chk.h asn1/ksudo.h

.endfor

.PHONY: asn1
asn1: asn1/ksudo.h

asn1/ksudo.h: asn1/ksudo.asn1
	${MAKE} -C asn1 asn1

asn1/asn1.o: asn1/ksudo.h
	${MAKE} -C asn1 all

clean:
	rm -f ${PROGS} ${OBJS}
	${MAKE} -C asn1 clean asn1clean
