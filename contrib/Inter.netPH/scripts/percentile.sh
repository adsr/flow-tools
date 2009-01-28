#!/bin/bash
# a very crude script that computes the 95th percentile and returns 
# the results by IP arranged by usage in octets
#
# usage: flow-cat -a <flowdir> | ./percentile.sh | flow-stat -f8 -S2
#
# William Emmanuel S. YU <wyu@ateneo.edu>
# Ateneo de Manila University, Philippines
#

# directories and files
NETFLOWDIR=/home/netflow
BINDIR=$NETFLOWDIR/bin
FLOWSPLITPROG=flow-split-orig
TMPDIR=/home/wyy/tmp

# data is piped into this script from standard input.
# execute split for break file into smaller chunks
$FLOWSPLITPROG -T300 -o $TMPDIR/slice

# count the upper five percent
COUNT=`ls -l $TMPDIR/slice* | wc -l`
LIMIT=`echo "($COUNT * 5) / 100" | bc`

# remove upper fix percent
for ((a=1; a <= LIMIT ; a++))  
do
  rm `ls -S1 $TMPDIR/slice* | head -1`
done    

# process summary. change this part to generate the report you want.
# data is piped out to standard output as not the break the tools
# architecture of flow-tools.
$BINDIR/flow-cat -a $TMPDIR/slice* 

# clean-up slices when done
rm $TMPDIR/slice* 
