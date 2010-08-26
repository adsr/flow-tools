#!/bin/env python

import subprocess
import re

A_re = re.compile('^(.+)-(\d+)-(.+)$', re.I)

def git_describe(ref):
  return subprocess.Popen(['git', 'describe', ref], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].splitlines()[0].strip()

ref = git_describe('HEAD')

while 1:
  try:
    n = git_describe('%s^1' % ref)
  except:
    break
  if not n:
    break

  x = A_re.match(n)
  if x:
    n = x.group(1)
  
  m = 'IN %s' % ref
  r = '%s..%s' % (n, ref)

  clog = subprocess.Popen(['git', 'shortlog', r], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]

  if clog.strip():
    print "          CHANGES %s:" % m
    print
    print clog
  ref = n
