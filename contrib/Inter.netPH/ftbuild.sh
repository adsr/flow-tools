#!/bin/sh

# $Id: ftbuild.sh,v 1.1.1.1 2002/05/14 02:03:11 wyy Exp $

if [ -x /usr/bin/whoami ]; then
  me=`whoami`
elif [ -x /usr/ucb/whoami ]; then
  me=`whoami`
else
  me='flowgeek'
fi


host=`hostname | sed -e 's/\..*//g'`
date=`date`

echo "#define FT_PROG_BUILD \"$me@$host on $date\"" > ftbuild.h

