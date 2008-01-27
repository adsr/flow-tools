man_MANS = flow-capture.1 flow-cat.1 flow-dscan.1 flow-expire.1 flow-export.1 flow-fanout.1 flow-filter.1 flow-gen.1 flow-header.1 flow-import.1 flow-merge.1 flow-print.1 flow-receive.1 flow-send.1 flow-split.1 flow-stat.1 flow-tools-examples.1 flow-tools.1 flow-tag.1 flow-nfilter.1 flow-report.1 flow-mask.1 flow-xlate.1 flow-rptfmt.1 flow-log2rrd.1 flow-rpt2rrd.1

man_SGMLS = flow-capture.sgml flow-cat.sgml flow-dscan.sgml flow-expire.sgml flow-export.sgml flow-fanout.sgml flow-filter.sgml flow-gen.sgml flow-header.sgml flow-import.sgml flow-merge.sgml flow-print.sgml flow-receive.sgml flow-send.sgml flow-split.sgml flow-stat.sgml flow-tools-examples.sgml flow-tools.sgml flow-xlate.sgml flow-tag.sgml flow-nfilter.sgml flow-report.sgml flow-mask.sgml flow-rptfmt.sgml flow-log2rrd.sgml flow-rpt2rrd.sgml

man_HTMLS = flow-capture.html flow-cat.html flow-dscan.html flow-expire.html flow-export.html flow-fanout.html flow-filter.html flow-gen.html flow-header.html flow-import.html flow-merge.html flow-print.html flow-receive.html flow-send.html flow-split.html flow-stat.html flow-tools-examples.html flow-tools.html flow-tag.html flow-nfilter.html flow-report.html flow-mask.html flow-xlate.html flow-rptfmt.html flow-log2rrd.html flow-rpt2rrd.html

EXTRA_DIST = $(man_SGMLS)
DISTCLEANFILES = $(man_MANS) $(man_HTMLS)

SUFFIXES = .sgml .1 .html

.sgml.1:
	docbook2man $(srcdir)/$*.sgml

.sgml.html:
	docbook2html $(srcdir)/$*.sgml

all-am: Makefile $(man_MANS) $(man_HTMLS)

