#!/usr/bin/env python
#
# test_radrequest.py
# Author: Alex Kozadaev (2014)
#

import libradi
import unittest


class RadiusRequestTest(unittest.TestCase):
    def setUp(self):
        self.request = libradi.RadiusAcctRequest("secret")
        self.assertIsNotNone(self.request)

    def tearDown(self):
        del(self.request)

    def test_request_create(self):
        self.assertIsNotNone(self.request)
        self.assertEquals("secret", self.request.secret)

    def test_add_avp(self):
        req_length = self.request.length
        avp = libradi.RadiusAvp("called-station-id", "1234567890")
        self.assertIsNotNone(avp)
        self.assertEquals(0, len(self.request.avp_list))
        self.request.add_avp(avp)
        self.assertEquals(req_length + len(avp), len(self.request))
        req_length = len(self.request)
        self.assertEquals(1, len(self.request.avp_list))

        avp = libradi.RadiusAvp("framed-ip-address", "10.0.0.1")
        self.assertIsNotNone(avp)
        self.request.add_avp(avp)
        self.assertEquals(req_length + len(avp), len(self.request))
        self.assertEquals(2, len(self.request.avp_list))

    def test_get_all_avp_content(self):
        avp1 = libradi.RadiusAvp("called-station-id", "1234567890")
        self.assertIsNotNone(avp1)
        self.request.add_avp(avp1)
        self.assertEquals(avp1.dump(), self.request.get_all_avps_contents())

        avp2 = libradi.RadiusAvp("framed-ip-address", "10.0.0.1")
        self.assertIsNotNone(avp2)
        self.request.add_avp(avp2)
        self.assertEquals("".join((avp1.dump(), avp2.dump())),
                self.request.get_all_avps_contents())

    def test_authenticator(self):
        self.fail("TODO: implement the authenticator test")

    def test_dump(self):
        self.fail("TODO: implement the dump test")

    def test_request_string(self):
        self.fail("TODO: implement the __str__ test")

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
