# $Id: Make.inc,v 1.2 2002/05/15 08:29:34 wyy Exp $ 
#
# Make.inc
#
# Inter.net Philippines Patches to Flow-tools
#
# Miguel A. Paraz <map@internet.org.ph>
# Inter.net Philippines 
# 
# William Emmanuel S. YU <wyu@ateneo.edu>
# Ateneo de Manila University, Philippines
#
# Requires Flow-Tools-0.57
# Copyright (c) 2001 Mark Fullmer and The Ohio State University
# All rights reserved.
#

# flow-tools header and library files
# change this to reflect the real location of the flowtools
# header files and library files
FLOWDIR=../..
BIN=/home/netflow/bin
#ADDFLAGS=-DDEBUG
FLOWINCDIR=$(FLOWDIR)/lib
FLOWLIBDIR=$(FLOWDIR)/lib
FLOWLIB=$(FLOWLIBDIR)/libft.a
PATINCDIR=libpatricia
PATLIB=$(PATINCDIR)/libpatricia.a
LIB=-lz

# some system specific stuff
SHELL=/bin/sh
MV=mv
RM=rm
CP=cp
MAKE=make
CC=gcc
LD_D=gcc -shared -Xlinker -x
JAVAC=javac
AR=ar r
RANLIB=ranlib
INSTALL=install
