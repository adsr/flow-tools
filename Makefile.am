SUBDIRS = lib src bin configs docs

EXTRA_DIST = utils/* \
 SECURITY contrib/* configs/*

dist-hook:
	rm -rf $(distdir)/contrib/CVS
	rm -rf $(distdir)/configs/CVS
	rm -rf $(distdir)/utils/CVS
	rm $(distdir)/lib/ftconfig.h
