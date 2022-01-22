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

    def test_get_supported_types(self):
        types = libradi.radtypes.get_supported_types()
        self.assertIsNotNone(types)
        self.assertEqual(list, type(types))
        self.assertIn("integer", types)
        self.assertIn("date", types)
        self.assertIn("byte", types)
        self.assertIn("ether", types)
        self.assertIn("tlv", types)

    def test_byte_type(self):
        byte = libradi.radtypes.get_type_instance("byte", 125)
        self.assertIsNotNone(byte)
        self.assertEqual(125, byte.value)
        self.assertEqual("B", byte.pattern)
        self.assertEqual(b"\x7d", byte.dump())

    def test_byte_type_multi(self):
        byte = libradi.radtypes.get_type_instance("byte", 0x11aa22bb, length=4)
        self.assertIsNotNone(byte)
        self.assertEqual(0x11aa22bb, byte.value)
        self.assertEqual("B", byte.pattern)
        self.assertEqual(4, byte.length)
        self.assertEqual(4, len(byte))
        self.assertEqual(b"\x11\xaa\x22\xbb", byte.dump())

    def test_byte_type_multi_nolength(self):
        byte = libradi.radtypes.get_type_instance("byte", 0x11aa22bb)
        self.assertIsNotNone(byte)
        self.assertEqual(0x11aa22bb, byte.value)
        self.assertEqual("B", byte.pattern)
        self.assertEqual(4, byte.length)
        self.assertEqual(4, len(byte))
        self.assertEqual(b"\x11\xaa\x22\xbb", byte.dump())

    def test_integer_type(self):
        integer = libradi.radtypes.get_type_instance("integer", 0x11f)
        self.assertIsNotNone(integer)
        self.assertEqual(287, integer.value)
        self.assertEqual("L", integer.pattern)
        self.assertEqual(b"\x00\x00\x01\x1f", integer.dump())

    def test_integer_type_many(self):
        integer = libradi.radtypes.get_type_instance("integer",
                                                     0x11aa22bb,
                                                     length=2)
        self.assertIsNotNone(integer)
        self.assertEqual(0x11aa22bb, integer.value)
        self.assertEqual("L", integer.pattern)
        self.assertEqual(2, integer.length)
        self.assertEqual(8, len(integer))
        self.assertEqual(b"\x00\x00\x00\x00\x11\xaa\x22\xbb", integer.dump())

    def test_integer_type_many_nolength(self):
        integer = libradi.radtypes.get_type_instance("integer", 0x11aa22bbccdd)
        self.assertIsNotNone(integer)
        self.assertEqual(0x11aa22bbccdd, integer.value)
        self.assertEqual("L", integer.pattern)
        self.assertEqual(2, integer.length)
        self.assertEqual(8, len(integer))
        self.assertEqual(b"\x00\x00\x11\xaa\x22\xbb\xcc\xdd", integer.dump())

    def test_short_type(self):
        short = libradi.radtypes.get_type_instance("short", 0x11f)
        self.assertIsNotNone(short)
        self.assertEqual(287, short.value)
        self.assertEqual("H", short.pattern)
        self.assertEqual(b"\x01\x1f", short.dump())

    def test_short_type_many(self):
        short = libradi.radtypes.get_type_instance("short",
                                                   0x11aa22bb,
                                                   length=2)
        self.assertIsNotNone(short)
        self.assertEqual(0x11aa22bb, short.value)
        self.assertEqual("H", short.pattern)
        self.assertEqual(2, short.length)
        self.assertEqual(4, len(short))
        self.assertEqual(b"\x11\xaa\x22\xbb", short.dump())

    def test_short_type_many_nolength(self):
        short = libradi.radtypes.get_type_instance("short", 0x11aa22bbcc)
        self.assertIsNotNone(short)
        self.assertEqual(0x11aa22bbcc, short.value)
        self.assertEqual("H", short.pattern)
        self.assertEqual(3, short.length)
        self.assertEqual(6, len(short))
        self.assertEqual(b"\x00\x11\xaa\x22\xbb\xcc", short.dump())

    def test_bits_to_ip4mask(self):
        with self.assertRaises(ValueError):
            libradi.radtypes.bits_to_ip4mask(33)
            libradi.radtypes.bits_to_ip4mask(-1)
        self.assertEqual("255.0.0.0", libradi.radtypes.bits_to_ip4mask(8))
        self.assertEqual("255.255.0.0", libradi.radtypes.bits_to_ip4mask(16))
        self.assertEqual("255.255.255.0", libradi.radtypes.bits_to_ip4mask(24))
        self.assertEqual("255.255.255.255",
                         libradi.radtypes.bits_to_ip4mask(32))
        self.assertEqual("255.255.248.0", libradi.radtypes.bits_to_ip4mask(21))

    def test_address_type_ipv4(self):
        addr = libradi.radtypes.get_type_instance("ipaddr", "10.0.0.1")
        self.assertIsNotNone(addr)
        self.assertEqual("10.0.0.1", addr.value)
        self.assertEqual(b"\x0a\x00\x00\x01", addr.bin_ip_string)
        self.assertEqual(4, len(addr))
        exp_bin = libradi.radtypes.get_type_instance("byte", 0x0a000001, 4)
        self.assertEqual(exp_bin.dump(), addr.dump())

    def test_address_type_ipv6(self):
        addr = libradi.radtypes.get_type_instance("ipaddr", "2001:abcd::1")
        self.assertIsNotNone(addr)
        self.assertEqual("2001:abcd::1", addr.value)
        self.assertEqual((b"\x20\x01\xab\xcd\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x01"), addr.bin_ip_string)
        self.assertEqual(16, len(addr))
        exp_bin = libradi.radtypes.get_type_instance(
            "byte", 0x2001abcd000000000000000000000001, 16)
        self.assertEqual(exp_bin.dump(), addr.dump())

    def test_address_type_ipv6_prefix(self):
        ipv6pref = libradi.radtypes.get_type_instance("ipv6prefix",
                                                      "2001:db4::/24")
        self.assertIsNotNone(ipv6pref)
        self.assertEqual(24, ipv6pref.mask)
        self.assertEqual("20010db4000000000000000000000000",
                         ipv6pref.bin_ip_string.hex())
        self.assertEqual(18, len(ipv6pref))
        self.assertEqual("001820010db4000000000000000000000000",
                         ipv6pref.dump().hex())

        ipv6pref = libradi.radtypes.get_type_instance("ipv6prefix",
                                                      "2001:cccc::1")
        self.assertIsNotNone(ipv6pref)
        self.assertEqual(128, ipv6pref.mask)
        self.assertEqual("2001cccc000000000000000000000001",
                         ipv6pref.bin_ip_string.hex())
        self.assertEqual(18, len(ipv6pref))
        self.assertEqual("00802001cccc000000000000000000000001",
                         ipv6pref.dump().hex())

    def test_text_type(self):
        addr = libradi.radtypes.get_type_instance("string", "helloworld")
        self.assertIsNotNone(addr)
        self.assertEqual("helloworld", addr.value)
        self.assertEqual(len("helloworld"), len(addr))
        self.assertEqual(b"helloworld", addr.dump())

    def test_date_type(self):
        date = libradi.radtypes.get_type_instance("date", 1407970742.713266747)
        self.assertIsNotNone(date)
        self.assertEqual(1407970742, date.value)
        self.assertEqual(4, len(date))
        self.assertEqual("53ebedb6", date.dump().hex())

    def test_ether_type(self):
        ether = libradi.radtypes.get_type_instance("ether",
                                                   "00:11:22:33:44:55")
        self.assertIsNotNone(ether)
        self.assertEqual("00:11:22:33:44:55", ether.value)
        self.assertEqual(6, len(ether))
        self.assertEqual("001122334455", ether.dump().hex())

    def test_tlv_type(self):
        tlv = libradi.radtypes.get_type_instance(
            "tlv", "0xf5/0x{}".format(bytes("hello world", "utf-8").hex()))
        self.assertIsNotNone(tlv)
        self.assertEqual(len("hello world") + 2, len(tlv))
        self.assertEqual(0xb, len(tlv.values[2]))
        self.assertEqual("f5" + "0b" + "68656c6c6f20776f726c64",
                         tlv.dump().hex())

        with self.assertRaises(ValueError):
            tlv_type = "0x01f5"
            tlv = libradi.radtypes.get_type_instance(
                "tlv", "0x{}/0x{}".format(tlv_type,
                                          bytes("hello world", "utf-8").hex()))
