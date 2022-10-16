SBINDIR=/usr/local/sbin
MANDIR=/usr/local/share/man/man1

VERSION=1.0.2

CC=cc
CFLAGS=-O2 -W -Wall -Wno-unused-parameter
LIBS=-lpcap

DISTFILES=ifpstat.c \
	ifpstat.h \
	net.c \
	output.c \
	strlcat.c \
	Makefile \
	ifpstat.1 \
	README.md

ifpstat: ifpstat.c net.c output.c strlcat.c
	$(CC) $(CFLAGS) ifpstat.c net.c output.c strlcat.c -o ifpstat $(LIBS)

clean:
	rm -f ifpstat ifpstat-$(VERSION).tar.gz

install: ifpstat
	mkdir -p $(SBINDIR)
	cp ifpstat $(SBINDIR)/ifpstat
	mkdir -p $(MANDIR)
	cp ifpstat.1 $(MANDIR)/ifpstat.1

uninstall:
	rm -f $(SBINDIR)/ifpstat
	rm -f $(MANDIR)/ifpstat.1

dist:
	mkdir -p dist/ifpstat-$(VERSION)
	cp $(DISTFILES) dist/ifpstat-$(VERSION)/
	tar chozf ifpstat-$(VERSION).tar.gz -C dist ifpstat-$(VERSION)/
	rm -r dist
