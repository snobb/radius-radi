#!/usr/bin/env python
#
# test_libradi.py
# Author: Alex Kozadaev (2014)
#

import libradi
import unittest


class AVPTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_attributes(self):
        self.assertEquals(454, len(libradi.dictionary.get_dictionary().attributes))

    def test_values(self):
        """NAS-Port-Type values are defined in several files.
        checking if its all in tact in the end"""
        attr = libradi.dictionary.get_attribute("nas-port-type")
        self.assertIsNotNone(attr)
        self.assertEquals(37, len(attr.attr_defined_values))
        attr = libradi.dictionary.get_attribute("DHCP-Parameter-Request-List")
        self.assertIsNotNone(attr)
        self.assertEquals(117, len(attr.attr_defined_values))

    def test_vendors(self):
        self.assertEquals(6, len(libradi.dictionary.get_dictionary().vendors))

    def test_attribute(self):
        attr = libradi.dictionary.get_attribute("f5-ltm-user-role")
        self.assertIsNotNone(attr)
        self.assertEquals(1, attr.attr_id)
        self.assertEquals("integer", attr.attr_type)
        self.assertIsNotNone(attr.attr_vendor)
        vendor = attr.attr_vendor
        self.assertEquals("F5", vendor.vendor_name)
        self.assertEquals(3375, vendor.vendor_id)

        self.assertTrue(attr.has_defined_values())
        values = attr.attr_defined_values
        # values are all strings and that is by design.
        # the convertion is to be done by the Type objects
        exp_values = set([
                ("Administrator", 0), ("Resource-Admin", 20),
                ("User-Manager", 40), ("Manager", 100),
                ("App-Editor", 300), ("Operator", 400),
                ("Guest", 700), ("Policy-Editor", 800),
                ("No-Access", 900)
                ])
        values = [(name, val.value) for name, val in iter(values)]
        self.assertEquals(exp_values, set(values))

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
