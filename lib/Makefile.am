AM_CFLAGS=-g -Wall -fPIC

# The snippet below is needed to create correct ftpaths.h

edit = sed \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g'

ftpaths.h: ftpaths.h.in Makefile
	rm -f $@ $@.tmp
	$(edit) '$(srcdir)/$@.in' >$@.tmp
	mv $@.tmp $@

CLEANFILES = ftpaths.h

include_HEADERS = ftlib.h ftqueue.h radix.h ftpaths.h ftconfig.h
lib_LTLIBRARIES = libft.la

libft_la_SOURCES = ftio.c ftswap.c ftencode.c ftdecode.c ftprof.c bit1024.c \
 fmt.c support.c ftfile.c fttlv.c ftmap.c ftrec.c fterr.c \
 ftchash.c ftsym.c radix.c fttag.c ftfil.c ftstat.c getdate.y ftxfield.c\
 ftmask.c ftvar.c ftxlate.c

libft_la_LIBADD = $(LTLIBOBJS) $(CRYPTOLIB)
