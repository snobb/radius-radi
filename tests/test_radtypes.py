#!/usr/bin/env python
#
# test_libradi.radtypes.py
# Author: Alex Kozadaev (2014)
#

import libradi
import unittest
import struct


class RadTypesTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_byte_type(self):
        byte = libradi.radtypes.get_type_instance("byte", 125)
        self.assertIsNotNone(byte)
        self.assertEquals(125, byte.value)
        self.assertEquals("B", byte.pattern)
        self.assertEquals("\x7d", byte.dump())

    def test_byte_type_multi(self):
        byte = libradi.radtypes.get_type_instance("byte", 0x11aa22bb, length=4)
        self.assertIsNotNone(byte)
        self.assertEquals(0x11aa22bb, byte.value)
        self.assertEquals("B", byte.pattern)
        self.assertEquals(4, byte.length)
        self.assertEquals(4, len(byte))
        self.assertEquals("\x11\xaa\x22\xbb", byte.dump())

    def test_integer_type(self):
        integer = libradi.radtypes.get_type_instance("integer", 0x11f)
        self.assertIsNotNone(integer)
        self.assertEquals(287, integer.value)
        self.assertEquals("L", integer.pattern)
        self.assertEquals("\x00\x00\x01\x1f", integer.dump())

    def test_integer_type_many(self):
        integer = libradi.radtypes.get_type_instance("integer", 0x11aa22bb, length=2)
        self.assertIsNotNone(integer)
        self.assertEquals(0x11aa22bb, integer.value)
        self.assertEquals("L", integer.pattern)
        self.assertEquals(2, integer.length)
        self.assertEquals(8, len(integer))
        self.assertEquals("\x00\x00\x00\x00\x11\xaa\x22\xbb", integer.dump())

    def test_short_type(self):
        short = libradi.radtypes.get_type_instance("short", 0x11f)
        self.assertIsNotNone(short)
        self.assertEquals(287, short.value)
        self.assertEquals("h", short.pattern)
        self.assertEquals("\x01\x1f", short.dump())

    def test_short_type_many(self):
        short = libradi.radtypes.get_type_instance("short", 0x11aa22bb, length=2)
        self.assertIsNotNone(short)
        self.assertEquals(0x11aa22bb, short.value)
        self.assertEquals("h", short.pattern)
        self.assertEquals(2, short.length)
        self.assertEquals(4, len(short))
        self.assertEquals("\x11\xaa\x22\xbb", short.dump())

    def test_bits_to_ip4mask(self):
        addr = libradi.radtypes.get_type_instance("ipaddr", "10.0.0.1")
        with self.assertRaises(ValueError) as cm:
            addr.bits_to_ip4mask(33)
            addr.bits_to_ip4mask(-1)
        self.assertEquals("255.0.0.0", addr.bits_to_ip4mask(8))
        self.assertEquals("255.255.0.0", addr.bits_to_ip4mask(16))
        self.assertEquals("255.255.255.0", addr.bits_to_ip4mask(24))
        self.assertEquals("255.255.255.255", addr.bits_to_ip4mask(32))
        self.assertEquals("255.255.248.0", addr.bits_to_ip4mask(21))

    def test_address_type_ipv4(self):
        addr = libradi.radtypes.get_type_instance("ipaddr", "10.0.0.1")
        self.assertIsNotNone(addr)
        self.assertEquals("10.0.0.1", addr.value)
        self.assertEquals("\x0a\x00\x00\x01", addr.bin_ip_string)
        self.assertEquals(4, len(addr))
        exp_bin = libradi.radtypes.get_type_instance("byte", 0x0a000001, 4)
        self.assertEquals(exp_bin.dump(), addr.dump())

    def test_address_type_ipv6(self):
        addr = libradi.radtypes.get_type_instance("ipaddr", "2001:abcd::1")
        self.assertIsNotNone(addr)
        self.assertEquals("2001:abcd::1", addr.value)
        self.assertEquals(("\x20\x01\xab\xcd\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x01"), addr.bin_ip_string)
        self.assertEquals(16, len(addr))
        exp_bin = libradi.radtypes.get_type_instance("byte",
                0x2001abcd000000000000000000000001, 16)
        self.assertEquals(exp_bin.dump(), addr.dump())

    def test_text_type(self):
        addr = libradi.radtypes.get_type_instance("string", "helloworld")
        self.assertIsNotNone(addr)
        self.assertEquals("helloworld", addr.value)
        self.assertEquals(len("helloworld"), len(addr))
        self.assertEquals("helloworld", addr.dump())

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
