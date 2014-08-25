#!/usr/bin/env python
#
# __init__.py
# Author: Alex Kozadaev (2014)
#

import sys
import unittest

sys.path.append("..")

for all_test_suite in unittest.defaultTestLoader.discover('.', pattern='test_*.py'):
    for test_suite in all_test_suite:
        if (len(test_suite._tests) > 0):
            print "testing: {}".format(test_suite._tests[0].__class__)
        unittest.TextTestRunner().run(test_suite)

# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
