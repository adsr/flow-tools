DOCSRC := flow-capture.sgml flow-cat.sgml flow-dscan.sgml flow-expire.sgml flow-export.sgml flow-fanout.sgml flow-filter.sgml flow-gen.sgml flow-header.sgml flow-import.sgml flow-merge.sgml flow-print.sgml flow-receive.sgml flow-send.sgml flow-split.sgml flow-stat.sgml flow-tools-examples.sgml flow-tools.sgml flow-xlate.sgml flow-tag.sgml flow-nfilter.sgml flow-report.sgml flow-mask.sgml flow-rptfmt.sgml flow-log2rrd.sgml flow-rpt2rrd.sgml

man_MANS := $(DOCSRC:.sgml=.1)
mantemplates := $(DOCSRC:.sgml=.1.in)
htmltemplates := $(DOCSRC:.sgml=.html.in)

dist_noinst_DATA := $(mantemplates) $(htmltemplates)
noinst_DATA := $(DOCSRC:%.sgml=%.html)

EXTRA_DIST := $(DOCSRC)
MAINTAINERCLEANFILES := $(mantemplates) $(htmltemplates)
CLEANFILES := $(man_MANS) $(noinst_DATA)
MOSTLYCLEANFILES := manpage.links manpage.refs

do_subst = sed -e 's,[@]sysconfdir[@],$(sysconfdir),g'

%.html: %.html.in
	$(do_subst) < $< > $@

%.html.in: %.sgml
	TMP=`mktemp -d` && \
	docbook2html -u $< -o $$TMP && \
	cat $$TMP/*.html > $@ && \
	rm -rf $$TMP

%.1: %.1.in
	$(do_subst) < $< > $@

%.1.in: %.sgml
	TMP=`mktemp -d` && \
	docbook2man $< -o $$TMP && \
	cat $$TMP/*.? > $@ && \
	rm -rf $$TMP
