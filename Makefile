# 
# Makefile for ksudo, a system to allow limited remote command execution
# based on Kerberos principals.
#
# Copyright 2012 Ben Morrow <ben@morrow.me.uk>
# Released under the 2-clause BSD licence.
#

CFLAGS_krb5!=	krb5-config --cflags krb5
CFLAGS+= 	-I. ${CFLAGS_krb5}

LIBS_krb5!=	krb5-config --libs krb5
LIBS+=		${LIBS_krb5}

all: asn1/asn1.o

asn1/ksudo.h: asn1/ksudo.asn1
	${MAKE} -C asn1 asn1

asn1/asn1.o: asn1/ksudo.h
	${MAKE} -C asn1 all

clean:
	${MAKE} -C asn1 clean asn1clean
