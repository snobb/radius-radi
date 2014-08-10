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
        username = libradi.RadiusAvp("user-name", "johndoe")
        status = libradi.RadiusAvp("acct-status-type", 1)
        nas_ip = libradi.RadiusAvp("nas-ip-address", "127.0.0.1")
        framed_ip = libradi.RadiusAvp("framed-ip-address", "10.0.0.1")
        framed_mask = libradi.RadiusAvp("framed-ip-netmask", "255.255.255.255")
        framed_proto = libradi.RadiusAvp("framed-protocol", 1)
        calling_id = libradi.RadiusAvp("calling-station-id", "00441234987654")
        called_id = libradi.RadiusAvp("called-station-id", "web.apn")
        imsi = libradi.RadiusAvp("3gpp-imsi", "12345678901234")
        imei = libradi.RadiusAvp("3gpp-imeisv", "3456789012345678901234567890")
        self.request.add_avp(username)
        self.request.add_avp(status)
        self.request.add_avp(nas_ip)
        self.request.add_avp(framed_ip)
        self.request.add_avp(framed_mask)
        self.request.add_avp(framed_proto)
        self.request.add_avp(calling_id)
        self.request.add_avp(called_id)
        self.request.add_avp(imsi)
        self.request.add_avp(imei)
        avps = self.request.get_all_avps_contents()
        # the result is recieved from a tcpdump from a packet created
        # with radtool package.
        self.assertEquals("cf00f8a8355d79ff820361f2567a9e95",
                self.request.compute_authenticator(avps).encode("hex"))

    def test_dump(self):
        self.fail("TODO: implement the dump test")

    def test_request_string(self):
        username = libradi.RadiusAvp("user-name", "johndoe")
        status = libradi.RadiusAvp("acct-status-type", 1)
        self.request.add_avp(username)
        self.request.add_avp(status)
        self.assertEquals(2, len(self.request.avp_list))
        avps = self.request.get_all_avps_contents()
        exp_str = ("REQUEST:  Code:{}  PID:{}  Length:{}  Auth:{}"
                "\n {}\n {}").format(
                        self.request.code,
                        self.request.pid,
                        len(self.request),
                        self.request.compute_authenticator(avps).encode("hex"),
                        self.request.avp_list[0],
                        self.request.avp_list[1])
        self.assertEquals(exp_str, str(self.request))

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
