#!/usr/bin/env python
#
# test_avp.py
# Author: Alex Kozadaev (2014)
#

import libradi
import unittest


class AVPTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_integer_avp(self):
        avp = libradi.RadiusAvp("3gpp-ms-time-zone", 100)
        self.assertIsNotNone(avp)
        self.assertTrue(avp.has_sub_avps())
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(10415, avp.avp_value.value)   # 3gpp value 10415
        # 3gpp-ms-time-zone
        self.assertEquals(23, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(100, avp.avp_subavp[0].avp_value.value) # 100

    def test_string_avp(self):
        avp = libradi.RadiusAvp("DHCP-Boot-File-Name", "hello_world")
        self.assertIsNotNone(avp)
        self.assertTrue(avp.has_sub_avps())
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(54, avp.avp_value.value)      # dhcp value 54
        self.assertEquals(67, avp.avp_subavp[0].avp_code.value)
        self.assertEquals("hello_world", avp.avp_subavp[0].avp_value.value)

    def test_string_no_vendor_avp(self):
        avp = libradi.RadiusAvp("Called-Station-Id", "1234567890")
        self.assertIsNotNone(avp)
        self.assertFalse(avp.has_sub_avps())
        self.assertEquals(30, avp.avp_code.value)
        self.assertEquals("1234567890", avp.avp_value.value)

    def test_integer_value_avp(self):
        avp = libradi.RadiusAvp("F5-LTM-User-Console", 1)
        self.assertIsNotNone(avp)
        self.assertTrue(avp.has_sub_avps())
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(3375, avp.avp_value.value)    # F5 networks 3375
        self.assertEquals(4, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(1, avp.avp_subavp[0].avp_value.value)

    def test_integer_value_avp(self):
        with self.assertRaises(ValueError):
            avp = libradi.RadiusAvp("F5-LTM-User-Console", 5)

        try:
            avp = libradi.RadiusAvp("F5-LTM-User-Console", 1)
        except ValueError as e:
            self.fail("raised {}: {}".format(type(e), e.message))

        self.assertIsNotNone(avp)
        self.assertTrue(avp.has_sub_avps())
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(3375, avp.avp_value.value)    # F5 networks 3375
        self.assertEquals(4, avp.avp_subavp[0].avp_code.value)
        self.assertEquals(1, avp.avp_subavp[0].avp_value.value)

    def test_avp_dump(self):
        avp = libradi.RadiusAvp("Calling-Station-Id", "00441234987654")
        self.assertEquals(31, avp.avp_code.value)
        binary = avp.dump()
        #exported from a tcpdump with a libradi packet
        exp_bin = libradi.radtypes.get_type_instance("byte",
                0x1f103030343431323334393837363534, 16)
        self.assertEquals(exp_bin.dump(), binary)

        avp = libradi.RadiusAvp("Called-Station-Id", "web.apn")
        self.assertEquals(30, avp.avp_code.value)
        #exported from a tcpdump with a libradi packet
        exp_bin = libradi.radtypes.get_type_instance("byte",
                0x1e097765622e61706e, len(avp))
        self.assertEquals(exp_bin.dump(), avp.dump())

    def test_avp_dump_vendor(self):
        avp = libradi.RadiusAvp("3GPP-IMSI", "12345678901234")
        self.assertIsNotNone(avp)
        self.assertTrue(avp.has_sub_avps())
        self.assertEquals(26, avp.avp_code.value)       # vendor-specific
        self.assertEquals(10415, avp.avp_value.value)   # 3GPP 10415
        #exported from a tcpdump with a libradi packet
        exp_bin = libradi.radtypes.get_type_instance("byte",
                0x1a16000028af01103132333435363738393031323334, len(avp))
        self.assertEquals(exp_bin.dump(), avp.dump())

    def test_avp_str(self):
        avp = libradi.RadiusAvp("Framed-IP-Address", "10.0.0.1")
        self.assertIsNotNone(avp)
        exp_str = ("AVP: Type:Framed-IP-Address(ipaddr)  Length:6  "
                "Value:10.0.0.1")
        self.assertEquals(exp_str, str(avp))

        avp = libradi.RadiusAvp("3GPP-IMSI", "123456789")
        self.assertIsNotNone(avp)
        exp_str = ("AVP: Type:Vendor-Specific(octets)  Length:17  "
                "Value:10415\n`- AVP: Type:3GPP-IMSI(string)  "
                "Length:11  Value:123456789")
        self.assertEquals(exp_str, str(avp))


# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
