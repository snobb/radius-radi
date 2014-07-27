#!/usr/bin/env python
#
# test_dictionary.py
# Author: Alex Kozadaev (2014)
#

import dictionary
import unittest


class AVPTest(unittest.TestCase):
    def setUp(self):
        self.rad_dict = dictionary.Dictionary()
        self.rad_dict.read_dictionary("dictionary", "tests/dict")


    def tearDown(self):
        del(self.rad_dict)


    def test_attributes(self):
        self.assertEquals(454, len(self.rad_dict.attributes))


    def test_values(self):
        """NAS-Port-Type values are defined in several files.
        checking if its all in tact in the end"""
        attr = self.rad_dict.get_attribute("nas-port-type")
        self.assertEquals(37, len(attr.attr_defined_values))
        attr = self.rad_dict.get_attribute("DHCP-Parameter-Request-List")
        self.assertEquals(117, len(attr.attr_defined_values))

    def test_vendors(self):
        self.assertEquals(6, len(self.rad_dict.vendors))

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
