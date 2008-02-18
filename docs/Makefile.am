DOCSRC := flow-capture.sgml flow-cat.sgml flow-dscan.sgml flow-expire.sgml flow-export.sgml flow-fanout.sgml flow-filter.sgml flow-gen.sgml flow-header.sgml flow-import.sgml flow-merge.sgml flow-print.sgml flow-receive.sgml flow-send.sgml flow-split.sgml flow-stat.sgml flow-tools-examples.sgml flow-tools.sgml flow-xlate.sgml flow-tag.sgml flow-nfilter.sgml flow-report.sgml flow-mask.sgml flow-rptfmt.sgml flow-log2rrd.sgml flow-rpt2rrd.sgml

dist_man_MANS := $(DOCSRC:%.sgml=%.1)

dist_noinst_DATA := $(DOCSRC:%.sgml=%.html)

EXTRA_DIST = $(DOCSRC)

.sgml.html:
	docbook2html -u $<

.sgml.1:
	docbook2man $<



