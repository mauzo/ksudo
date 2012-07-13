
all: asn1.o

ASN1_COMPILE=	/usr/local/libexec/heimdal/asn1_compile

ASN1_H=	ksudo.h ksudo-priv.h

CFLAGS?= 	-g 
CFLAGS+=	-I. -I/usr/local/include

.if exists(ksudo_files)

ASN1_X!= cat ksudo_files
ASN1_O= ${ASN1_X:S/.x$/.o/}

asn1.o: ${ASN1_O} ${ASN1_H}
	ld -r -o ${.TARGET} ${ASN1_O}

.endif

asn1: asn1clean
	${ASN1_COMPILE} ksudo.asn1
	for x in $$(cat ksudo_files); \
	do \
		../mv-if-diff $$x $${x%.x}.c; \
	done
	for h in ${ASN1_H}; \
	do \
		../mv-if-diff $${h}x $$h; \
	done

asn1clean:
	rm -f ${ASN1_X:S/.x$/.c/} ${ASN1_H}
	rm -f ksudo_files ksudo-template.c

clean:
	rm -f ${ASN1_O} asn1.o
