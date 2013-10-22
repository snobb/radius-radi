#!/usr/bin/env python
#
# functions_tests.py
# Author: Alex Kozadaev (C) 2013
#

import unittest
from radi import bits_to_ip4mask

class testFunctionClass(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_bits_to_ip4mask(self):
        with self.assertRaises(ValueError) as cm:
            bits_to_ip4mask(33)
            bits_to_ip4mask(-1)
        self.assertEquals("255.0.0.0", bits_to_ip4mask(8))
        self.assertEquals("255.255.0.0", bits_to_ip4mask(16))
        self.assertEquals("255.255.255.0", bits_to_ip4mask(24))
        self.assertEquals("255.255.255.255", bits_to_ip4mask(32))
        self.assertEquals("255.255.248.0", bits_to_ip4mask(21))


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSequenceFunctions)
    unittest.TextTestRunner().run(suite)


# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
