#!/usr/bin/env python
#
# test_radmessage.py
# Author: Alex Kozadaev (2014)
#

import libradi
import unittest


class RadiusMessageTest(unittest.TestCase):

    def setUp(self):
        self.request = libradi.RadiusMessage("secret")
        self.assertIsNotNone(self.request)

    def tearDown(self):
        del (self.request)

    def test_request_create(self):
        self.assertIsNotNone(self.request)
        self.assertEqual("secret", self.request.secret)

    def test_add_avp(self):
        req_length = self.request.length
        avp = libradi.RadiusAvp("called-station-id", "1234567890")
        self.assertIsNotNone(avp)
        self.assertEqual(0, len(self.request.avp_list))
        self.request.add_avp(avp)
        self.assertEqual(req_length + len(avp), len(self.request))
        req_length = len(self.request)
        self.assertEqual(1, len(self.request.avp_list))

        avp = libradi.RadiusAvp("framed-ip-address", "10.0.0.1")
        self.assertIsNotNone(avp)
        self.request.add_avp(avp)
        self.assertEqual(req_length + len(avp), len(self.request))
        self.assertEqual(2, len(self.request.avp_list))

    def test_get_all_avp_content(self):
        avp1 = libradi.RadiusAvp("called-station-id", "1234567890")
        self.assertIsNotNone(avp1)
        self.request.add_avp(avp1)
        self.assertEqual(avp1.dump(), self.request.get_all_avps_contents())

        avp2 = libradi.RadiusAvp("framed-ip-address", "10.0.0.1")
        self.assertIsNotNone(avp2)
        self.request.add_avp(avp2)
        self.assertEqual(b"".join((avp1.dump(), avp2.dump())),
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
        self.assertEqual("cf00f8a8355d79ff820361f2567a9e95",
                         self.request.compute_authenticator(avps).hex())

    def test_dump(self):
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
        # exported from the tcpdump
        exp_message = (
            "04f5008ecf00f8a8355d79ff820361f2567a9e9501096a6f686e"
            "646f6528060000000104067f00000108060a0000010906ffffffff07060"
            "00000011f1030303434313233343938373635341e097765622e61706e1a"
            "16000028af011031323334353637383930313233341a24000028af141e3"
            "3343536373839303132333435363738393031323334353637383930")
        self.assertEqual(exp_message, self.request.dump().hex())

    def test_request_string(self):
        username = libradi.RadiusAvp("user-name", "johndoe")
        status = libradi.RadiusAvp("acct-status-type", 1)
        self.request.add_avp(username)
        self.request.add_avp(status)
        self.assertEqual(2, len(self.request.avp_list))
        avps = self.request.get_all_avps_contents()
        exp_str = ("REQUEST:  Code:{}  PID:{}  Length:{}  Auth:{}"
                   "\n {}\n {}").format(
                       self.request.code, self.request.pid, len(self.request),
                       self.request.compute_authenticator(avps).hex(),
                       self.request.avp_list[0], self.request.avp_list[1])
        self.assertEqual(exp_str, str(self.request))
