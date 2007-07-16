## Process this file with automake to produce Makefile.in

#AM_CFLAGS=-g -Wall -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs
#AM_CFLAGS=-O2
AM_CFLAGS=-g -Wall -fPIC

# DEFS=-I. -I$(srcdir)/lib

include_HEADERS = ftlib.h ftqueue.h radix.h ftpaths.h ftconfig.h
lib_LTLIBRARIES = libft.la

libft_la_SOURCES = ftio.c ftswap.c ftencode.c ftdecode.c ftprof.c bit1024.c \
 fmt.c support.c ftfile.c fttlv.c ftmap.c ftrec.c fterr.c \
 ftchash.c ftsym.c radix.c fttag.c ftfil.c ftstat.c getdate.y ftxfield.c\
 ftmask.c ftvar.c ftxlate.c

libft_la_LIBADD = $(LTLIBOBJS) $(CRYPTOLIB)

