
noinst_HEADERS = flow-dscan.h pcap.h cflowd.h acl2.h aclyacc.h

EXTRA_DIST = ftbuild.sh

DEFS=-I$(srcdir)/../lib -L$(srcdir)/../lib 

#AM_CFLAGS=-g -Wall -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs
#AM_CFLAGS=-O2
#AM_CFLAGS=-g -Wall

bin_PROGRAMS = flow-capture flow-cat flow-stat flow-print flow-dscan \
        flow-send flow-receive flow-gen flow-expire \
        flow-filter flow-export flow-header flow-split \
	flow-xlate flow-merge flow-import flow-fanout flow-tag \
	flow-nfilter flow-report flow-mask

#force_build:
#
#ftbuild.h: ftbuild.sh force_build
#	./ftbuild.sh

flow_mask_SOURCES = flow-mask.c ftbuild.h
flow_mask_LDFLAGS = -L../lib
flow_mask_LDADD =  -lft
flow_mask_DEPENDENCIES = ftbuild.h

flow_report_SOURCES = flow-report.c ftbuild.h
flow_report_LDFLAGS = -L../lib
flow_report_LDADD =  -lft
flow_report_DEPENDENCIES = ftbuild.h

flow_nfilter_SOURCES = flow-nfilter.c ftbuild.h
flow_nfilter_LDFLAGS = -L../lib
flow_nfilter_LDADD =  -lft
flow_nfilter_DEPENDENCIES = ftbuild.h

flow_import_SOURCES = flow-import.c ftbuild.h
flow_import_LDFLAGS = -L../lib
flow_import_LDADD =  -lft
flow_import_DEPENDENCIES = ftbuild.h

flow_merge_SOURCES = flow-merge.c
flow_merge_LDFLAGS = -L../lib
flow_merge_LDADD =  -lft
flow_merge_DEPENDENCIES = ftbuild.h

flow_capture_SOURCES = flow-capture.c
flow_capture_LDFLAGS = -L../lib
flow_capture_LDADD =  -lft @CRYPTOLIB@
flow_capture_DEPENDENCIES = ftbuild.h

flow_cat_SOURCES = flow-cat.c
flow_cat_LDFLAGS = -L../lib
flow_cat_LDADD =  -lft
flow_cat_DEPENDENCIES = ftbuild.h

flow_stat_SOURCES = flow-stat.c
flow_stat_LDFLAGS = -L../lib
flow_stat_LDADD =  -lft
flow_stat_DEPENDENCIES = ftbuild.h

flow_print_SOURCES = flow-print.c
flow_print_LDFLAGS = -L../lib
flow_print_LDADD =  -lft
flow_print_DEPENDENCIES = ftbuild.h

flow_dscan_SOURCES = flow-dscan.c
flow_dscan_LDFLAGS = -L../lib
flow_dscan_LDADD =  -lft
flow_dscan_DEPENDENCIES = ftbuild.h

flow_fanout_SOURCES = flow-fanout.c
flow_fanout_LDFLAGS = -L../lib
flow_fanout_LDADD =  -lft
flow_fanout_DEPENDENCIES = ftbuild.h

flow_send_SOURCES = flow-send.c
flow_send_LDFLAGS = -L../lib
flow_send_LDADD =  -lft
flow_send_DEPENDENCIES = ftbuild.h

flow_receive_SOURCES = flow-receive.c
flow_receive_LDFLAGS = -L../lib
flow_receive_LDADD =  -lft
flow_receive_DEPENDENCIES = ftbuild.h

flow_gen_SOURCES = flow-gen.c
flow_gen_LDFLAGS = -L../lib
flow_gen_LDADD =  -lft
flow_gen_DEPENDENCIES = ftbuild.h

flow_expire_SOURCES = flow-expire.c
flow_expire_LDFLAGS = -L../lib
flow_expire_LDADD =  -lft
flow_expire_DEPENDENCIES = ftbuild.h

flow_filter_SOURCES = flow-filter.c aclyacc.y acllex.l acl2.c 
flow_filter_LDFLAGS = -L../lib
flow_filter_LDADD =  -lft @LEXLIB@ @YLIB@
flow_filter_DEPENDENCIES = ftbuild.h

flow_export_SOURCES = flow-export.c
flow_export_LDFLAGS = -L../lib $(MYSQLLDFLAGS) $(PGSQLLDFLAGS)
flow_export_CFLAGS = $(MYSQLCFLAGS) $(PGSQLCFLAGS)
flow_export_LDADD =  -lft $(MYSQLLIB) $(PGSQLLIB)
flow_export_DEPENDENCIES = ftbuild.h

flow_header_SOURCES = flow-header.c
flow_header_LDFLAGS = -L../lib
flow_header_LDADD =  -lft
flow_header_DEPENDENCIES = ftbuild.h

flow_split_SOURCES = flow-split.c
flow_split_LDFLAGS = -L../lib
flow_split_LDADD =  -lft
flow_split_DEPENDENCIES = ftbuild.h

flow_xlate_SOURCES = flow-xlate.c
flow_xlate_LDFLAGS = -L../lib $(CRYPTOLDFLAGS)
flow_xlate_LDADD =  -lft $(CRYPTOLIB)
flow_xlate_DEPENDENCIES = ftbuild.h

flow_tag_SOURCES = flow-tag.c
flow_tag_LDFLAGS = -L../lib
flow_tag_LDADD =  -lft
flow_tag_DEPENDENCIES = ftbuild.h

