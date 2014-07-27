#!/usr/bin/env python
#
# test_avp.py
# Author: Alex Kozadaev (2014)
#

import types
import radius, dictionary
import unittest


rad_dict = dictionary.Dictionary()
rad_dict.read_dictionary("dictionary", "tests/dict")

class AVPTest(unittest.TestCase):
    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_radus_avp(self):
        self.fail("not implemented")


# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
