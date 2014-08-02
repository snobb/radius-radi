#!/usr/bin/env python
#
# test_avp.py
# Author: Alex Kozadaev (2014)
#

import radius, dictionary
import unittest


class AVPTest(unittest.TestCase):
    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_integer_avp(self):
        avp = radius.RadiusAvp("3gpp-ms-time-zone", 100)
        self.assertIsNotNone(avp)
        self.assertEquals(1, len(avp.avp_subavp))
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(10415, avp.avp_value.value)   # 3gpp value 10415
        # 3gpp-ms-time-zone
        self.assertEquals(23, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(100, avp.avp_subavp[0].avp_value.value) # 100


    def test_string_avp(self):
        avp = radius.RadiusAvp("DHCP-Boot-File-Name", "hello_world")
        self.assertIsNotNone(avp)
        self.assertEquals(1, len(avp.avp_subavp))
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(54, avp.avp_value.value)   # dhcp value 54
        self.assertEquals(67, avp.avp_subavp[0].avp_code.value)
        self.assertEquals("hello_world", avp.avp_subavp[0].avp_value.value)


    def test_string_no_vendor_avp(self):
        avp = radius.RadiusAvp("Called-Station-Id", "1234567890")
        self.assertIsNotNone(avp)
        self.assertEquals(0, len(avp.avp_subavp))
        self.assertEquals(30, avp.avp_code.value)
        self.assertEquals("1234567890", avp.avp_value.value)


    def test_integer_value_avp(self):
        avp = radius.RadiusAvp("F5-LTM-User-Console", 1)
        self.assertIsNotNone(avp)
        self.assertEquals(1, len(avp.avp_subavp))
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(3375, avp.avp_value.value)    # F5 networks 3375
        self.assertEquals(4, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(1, avp.avp_subavp[0].avp_value.value)

    def test_integer_value_avp(self):
        with self.assertRaises(ValueError):
            avp = radius.RadiusAvp("F5-LTM-User-Console", 5)
        self.assertIsNotNone(avp)
        self.assertEquals(1, len(avp.avp_subavp))
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(3375, avp.avp_value.value)    # F5 networks 3375
        self.assertEquals(4, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(1, avp.avp_subavp[0].avp_value.value)

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
