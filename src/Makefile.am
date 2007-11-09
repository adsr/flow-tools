
noinst_HEADERS = flow-dscan.h pcap.h cflowd.h acl2.h

BUILT_SOURCES = aclyacc.h
AM_YFLAGS = -d

EXTRA_DIST = ftbuild.sh
CLEANFILES = ftbuild.h

DEFS=-I$(srcdir)/../lib

bin_PROGRAMS = flow-capture flow-cat flow-stat flow-print flow-dscan \
        flow-send flow-receive flow-gen flow-expire \
        flow-filter flow-export flow-header flow-split \
	flow-xlate flow-merge flow-import flow-fanout flow-tag \
	flow-nfilter flow-report flow-mask

ftbuild.h: ftbuild.sh
	./ftbuild.sh $@

LDADD = ../lib/libft.la
AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)

flow_capture_SOURCES = flow-capture.c
flow_capture_LDADD =  $(LDADD) $(CRYPTOLIB)

flow_filter_SOURCES = flow-filter.c aclyacc.y acllex.l acl2.c 
flow_filter_LDADD = $(LDADD) $(LEXLIB)
flow_export_SOURCES = flow-export.c
flow_export_LDFLAGS = $(AM_LDFLAGS) $(MYSQLLDFLAGS) $(POSTGRESQL_LDFLAGS)
flow_export_CFLAGS = $(AM_CFLAGS) $(MYSQLCFLAGS) $(POSTGRESQL_CFLAGS)
flow_export_LDADD =  $(LDADD) $(MYSQLLIB) $(POSTGRESQL_LIB)
flow_xlate_LDFLAGS =  $(AM_LDFLAGS) $(CRYPTOLDFLAGS)
flow_xlate_LDADD = $(LDADD) $(CRYPTOLIB)

