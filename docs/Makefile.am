man_MANSIN = flow-capture.1.in flow-cat.1 flow-dscan.1 flow-expire.1 flow-export.1 flow-fanout.1.in flow-filter.1 flow-gen.1 flow-header.1 flow-import.1 flow-merge.1 flow-print.1.in flow-receive.1.in flow-send.1 flow-split.1 flow-stat.1 flow-tools-examples.1 flow-tools.1 flow-tag.1.in flow-nfilter.1.in flow-report.1.in flow-mask.1.in flow-xlate.1.in flow-rptfmt.1.in flow-log2rrd.1.in flow-rpt2rrd.1.in

man_MANS = flow-capture.1 flow-cat.1 flow-dscan.1 flow-expire.1 flow-export.1 flow-fanout.1 flow-filter.1 flow-gen.1 flow-header.1 flow-import.1 flow-merge.1 flow-print.1 flow-receive.1 flow-send.1 flow-split.1 flow-stat.1 flow-tools-examples.1 flow-tools.1 flow-tag.1 flow-nfilter.1 flow-report.1 flow-mask.1 flow-xlate.1 flow-rptfmt.1 flow-log2rrd.1 flow-rpt2rrd.1

man_SGMLS = flow-capture.sgml flow-cat.sgml flow-dscan.sgml flow-expire.sgml flow-export.sgml flow-fanout.sgml flow-filter.sgml flow-gen.sgml flow-header.sgml flow-import.sgml flow-merge.sgml flow-print.sgml flow-receive.sgml flow-send.sgml flow-split.sgml flow-stat.sgml flow-tools-examples.sgml flow-tools.sgml flow-xlate.sgml flow-tag.sgml flow-nfilter.sgml flow-report.sgml flow-mask.sgml flow-rptfmt.sgml flow-log2rrd.sgml flow-rpt2rrd.sgml

man_HTMLSIN = flow-capture.html.in flow-cat.html flow-dscan.html flow-expire.html flow-export.html flow-fanout.html.in flow-filter.html flow-gen.html flow-header.html flow-import.html flow-merge.html flow-print.html.in flow-receive.html.in flow-send.html flow-split.html flow-stat.html flow-tools-examples.html flow-tools.html flow-xlate.html.in flow-tag.html.in flow-nfilter.html.in flow-report.html.in flow-mask.html.in flow-xlate.html flow-rptfmt.html.in flow-log2rrd.html.in flow-rpt2rrd.html.in

man_HTMLS = flow-capture.html flow-cat.html flow-dscan.html flow-expire.html flow-export.html flow-fanout.html flow-filter.html flow-gen.html flow-header.html flow-import.html flow-merge.html flow-print.html flow-receive.html flow-send.html flow-split.html flow-stat.html flow-tools-examples.html flow-tools.html flow-tag.html flow-nfilter.html flow-report.html flow-mask.html flow-xlate.html flow-rptfmt.html flow-log2rrd.html flow-rpt2rrd.html

EXTRA_DIST = $(man_MANSIN) $(man_SGMLS) $(man_HTMLSIN)

SUFFIXES = .sgml .1 .html .1.in .html.in

.sgml.1:
	docbook-to-man $*.sgml > $*.1

.sgml.1.in:
	docbook-to-man $*.sgml > $*.1.in
 
.sgml.html:
	openjade -V nochunks -c /usr/share/sgml/docbook/dsssl/modular/catalog -c /usr/local/share/sgml/docbook/catalog -c /usr/local/share/sgml/jade/catalog -d /usr/local/share/sgml/docbook/dsssl/modular/html/docbook.dsl -t sgml $*.sgml > $*.html

.sgml.html.in:
	openjade -V nochunks -c /usr/share/sgml/docbook/dsssl/modular/catalog -c /usr/local/share/sgml/docbook/catalog -c /usr/local/share/sgml/jade/catalog -d /usr/local/share/sgml/docbook/dsssl/modular/html/docbook.dsl -t sgml $*.sgml > $*.html.in

all-am: Makefile $(man_MANSIN) $(man_HTMLS)

