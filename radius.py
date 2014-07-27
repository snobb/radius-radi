#!/usr/bin/env python
#
# radius.py
# Author: Alex Kozadaev (2014)
#

import types
from dictionary import Dictionary

dictionary = Dictionary()

class RadiusAvp(object):
    """Radius avp implementations"""
    def __init__(self, avp_name, avp_value, allow_child=True):
        self.children = []
        self.avp_def = dictionary.get_attribute(avp_name.lower())

        if (allow_child and self.avp_def.attr_vendor):
            self.avp_def = dictionary.get_attribute("vendor-specific")
            children.append(RadiusAvp(avp_name, avp_value, False))

        self.avp_code = types.get_type_instance(
                "integer",
                self.avp_def.attr_id)

        self.avp_value = types.get_type_instance(
                self.avp_def.attr_type,
                avp_value)


    def dump(self):
        """dump the binary representation of the AVP"""
        value = struct.pack(RADIUS_AVP_TMPL % len(self.avp_value),
                self.avp_type,
                len(self),
                self.avp_value.dump())
        if self.vsa_child:
            return "".join((value, self.vsa_child.dump()))
        return value


    def __len__(self):
        children_len = sum(map(lambda child: len(child), self.children))
        return 2 + len(self.avp_value) + children_len


    def __str__(self):
        contents = ["AVP: Type:{}({})  Length:{}  Value:{}\n".format(
                self.avp_def.attr_name, self.avp_type,
                len(self),
                str(self.avp_value))]
        if len(self.children) > 0:
            for child in self.children():
                contents.append("\n{}".format(str(child)))
        return "\n".join((avp, "`- %s" % str(self.vsa_child)))



class RadiusAcctRequest(object):
    """Radius accounting request object"""
    def __init__(self, secret):
        self.code = 4
        self.pid = 0xf5
        self.length = 20    # length so far
        self.secret = secret
        self.avp_list = []


    def add_avp(self, avp):
        """add an AVP class to the list of the packets AVPs"""
        if avp and isinstance(avp, RadiusAvp):
            self.avp_list.append(avp)
            self.length += len(avp)


    def get_all_avps_contents(self):
        """return binary contents of all AVPs in the requests"""
        return "".join([avp.dump() for avp in self.avp_list])


    def compute_authenticator(self, avps):
        """gets the avp binary contents as an argument and returns computed
        authenticator of the radius request"""
        if not avps:
            raise ValueError("AVPs contents isn't defined")
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                len(self),
                bytes(IntegerType(0, length=4)))
        packet = "".join([header, avps, self.secret])
        return hashlib.md5(packet).digest()


    def dump(self):
        """dump binary version of the Radius Request packet payload
        including AVPs"""
        avps = self.get_all_avps_contents()
        auth = self.compute_authenticator(avps)
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                len(self),
                auth)
        return "".join([header, avps])


    def __len__(self):
        return self.length


    def __str__(self):
        auth = self.compute_authenticator(self.get_all_avps_contents())
        header = "HEADER:  Code:{%d}  PID{%d}  Length:{%d}  Auth{%s}\n" % (
                self.code, self.pid, len(self), auth.encode("hex"))
        avps = "".join([str(avp) for avp in self.avp_list])
        return "".join((header, avps))




# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
