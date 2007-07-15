#!/bin/sh

# $Id: ftbuild.sh,v 1.6 2003/04/02 18:03:03 maf Exp $

if [ -x /usr/bin/whoami ]; then
  me=`whoami`
elif [ -x /usr/ucb/whoami ]; then
  me=`whoami`
else
  me='flowgeek'
fi


host=`hostname | sed -e 's/\..*//g'`
date=`date`

echo "#define FT_PROG_BUILD \"$me@$host on $date\"" > $1

