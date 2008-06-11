#!/bin/env python

import subprocess

tags = filter(lambda x: "-rc" not in x, map(lambda x: x.strip(), subprocess.Popen(['git', 'tag', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].splitlines()))

upper = len(tags) - 1

for i in xrange(upper, -1, -1):
  if i == upper:
    first = tags[i]
    last = ''
    m = 'AFTER %s' % tags[i]
  elif i == -1:
    first = ''
    last = tags[i+1]
    m = 'IN %s' % tags[i+1]
  else:
    first = tags[i]
    last = tags[i+1]
    m = 'IN %s' % tags[i+1]

  r = '%s..%s' % (first, last)

  clog = subprocess.Popen(['git', 'shortlog', r], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]

  if not clog.strip():
    continue

  print "          CHANGES %s:" % m
  print
  print clog

