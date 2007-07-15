SUBDIRS = lib src bin configs docs utils

EXTRA_DIST = SECURITY contrib

dist-hook:
	rm -rf $(distdir)/contrib/CVS
	rm -rf $(distdir)/configs/CVS
	rm -rf $(distdir)/utils/CVS
	rm $(distdir)/lib/ftconfig.h
