#!/usr/bin/env python
#
# radius.py
# Author: Alex Kozadaev (2014)
#

import struct
import hashlib
import socket
import radtypes
import dictionary

# Radius-Request
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Code      |  Identifier   |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |                     Request Authenticator                     |
#   |                                                               |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Attributes ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-

# Regular AVP
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Length     |             Value
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              Value (cont)         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# String VSA (normally encapsulated in a AVP)
#    0                   1                   2
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Length     |  String ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RadiusAvp:
    """Radius avp implementations"""

    def __init__(self, avp_name, avp_value, allow_child=True):
        self.avp_subavp = []
        self.avp_def = dictionary.get_attribute(avp_name.lower())

        vendor = self.avp_def.attr_vendor
        if (allow_child and vendor):
            self.avp_def = dictionary.get_attribute("vendor-specific")
            self.avp_code = radtypes.get_type_instance("byte",
                                                       self.avp_def.attr_id)
            self.avp_value = radtypes.get_type_instance(
                "integer", vendor.vendor_id)
            self.avp_subavp.append(RadiusAvp(avp_name, avp_value, False))
        else:
            self.avp_code = radtypes.get_type_instance("byte",
                                                       self.avp_def.attr_id)
            self.avp_value = radtypes.get_type_instance(
                self.avp_def.attr_type, avp_value)
        self.validate_values()

    def validate_values(self):
        """check if the values are in the allowed range in case the AVP has
        a list of defined values"""
        if self.avp_def.has_defined_values():
            defined_values = dict(self.avp_def.attr_defined_values)
            if self.avp_value not in defined_values.values():
                raise ValueError(
                    f"{self.avp_def.attr_name} - value {self.avp_value} "
                    "is not allowed")

        return True

    def has_sub_avps(self):
        return len(self.avp_subavp) > 0

    def dump(self):
        """dump the binary representation of the AVP"""
        value = [
            self.avp_code.dump(),
            radtypes.get_type_instance("byte", len(self)).dump(),
            self.avp_value.dump()
        ]

        if self.has_sub_avps():
            subavps = [subavp.dump() for subavp in self.avp_subavp]
            return b"".join(value + subavps)
        return b"".join(value)

    def __len__(self):
        avp_subavp_len = sum(map(lambda child: len(child), self.avp_subavp))
        return 2 + len(self.avp_value) + avp_subavp_len

    def __str__(self):
        contents = [
            f"AVP: Type:{self.avp_def.attr_name}({self.avp_def.attr_type}) "
            f"Length:{len(self)} Value:{str(self.avp_value)}"
        ]
        if self.has_sub_avps():
            for subavp in self.avp_subavp:
                contents.append(f" `- {str(subavp)}")
        return "\n".join(contents)


class RadiusMessage:
    # Radius header templates
    RADIUS_HDR_TMPL = "!BBH16s"
    """Radius Message object"""

    def __init__(self, secret, code=4):
        self.code = code
        self.pid = 0xf5
        self.length = 20  # length so far
        self.secret = secret
        self.avp_list = []

    def add_avp(self, avp):
        """add an AVP class to the list of the packets AVPs"""
        if avp and isinstance(avp, RadiusAvp):
            self.avp_list.append(avp)
            self.length += len(avp)

    def get_all_avps_contents(self):
        """return binary contents of all AVPs in the requests"""
        return b"".join([avp.dump() for avp in self.avp_list])

    def compute_authenticator(self, avps):
        """gets the avp binary contents as an argument and returns computed
        authenticator of the radius request"""
        if not avps:
            raise ValueError("AVPs contents isn't defined")
        header = struct.pack(RadiusMessage.RADIUS_HDR_TMPL,
                             self.code, self.pid, len(self),
                             bytes(chr(0x00) * 16, "utf-8"))
        packet = b"".join([header, avps, bytes(self.secret, "utf-8")])
        return hashlib.md5(packet).digest()

    def dump(self):
        """dump binary version of the Radius Request packet payload
        including AVPs"""
        avps = self.get_all_avps_contents()
        auth = self.compute_authenticator(avps)
        header = struct.pack(RadiusMessage.RADIUS_HDR_TMPL, self.code,
                             self.pid, len(self), auth)
        return b"".join([header, avps])

    def send(self, destTuple):
        """send the packet to the network
        dest_tuple should be (dest_ip, dest_port)"""
        if ":" in destTuple[0]:  # is IPv6
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 20)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
        sock.sendto(self.dump(), destTuple)
        sock.close()

    def __len__(self):
        return self.length

    def __str__(self):
        auth = self.compute_authenticator(self.get_all_avps_contents())
        header = "REQUEST:  Code:{}  PID:{}  Length:{}  Auth:{}\n".format(
            self.code, self.pid, len(self), auth.hex())
        avps = "\n".join([f" {str(avp)}" for avp in self.avp_list])
        return "".join((header, avps))
