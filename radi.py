#!/usr/bin/env python
#
# radi.py
#

import argparse
import struct
import socket
import hashlib

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

# Radius accounting header templates
RADIUS_HDR_TMPL="!BBH16s"
RADIUS_AVP_TMPL="!BB%ss"

# actions
RESTART, START, STOP = range(3) # also ACCT_STATUS_TYPE start/stop

# Attributes
AVP_TYPE = {
    "NAS_IP_Addr" : 4,
    "Framed_Protocol" : 7,
    "Framed_IP_Addr" : 8,
    "Vendor_Specific" : 26,
    "Called_Station_Id" : 30,
    "Calling_Station_Id" : 31,
    "Acct_Status_Type" : 40,
    "3GPP_IMSI" : 1,
    "3GPP_IMEISV" : 20,
}

# Values
FRAMED_PROTO_PPP = 1

class Data(object):
    """data storage object"""
    def __init__(self):
        self.radiusDest = "127.0.0.1"
        self.radiusPort = 1813
        self.radiusSecret = "secret"
        self.verbose = False
        self.subsId="12345678912345"
        self.subsType="imsi"
        self.framedIp="10.0.0.1"


def parseArgs(data):
    """parse arguments"""
    parser = argparse.ArgumentParser(
            description="Radius accounting session management tool",
            argument_default=argparse.SUPPRESS)

    parser.add_argument("-d", "--destination", dest="radiusDest",
            help="ip of radius endpoint", required=False)

    parser.add_argument("-p", "--secret", dest="radiusSecret",
            help="radius secret")

    # mutually exclusive actions (start/stop/restart)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", "--start", dest="action", required=False,
            action="store_const", const=START, default=START,
            help="Start session")

    group.add_argument("-T", "--stop", dest="action", required=False,
            action="store_const", const=STOP, help="Stop session")

    group.add_argument("-R", "--restart", dest="action", required=False,
            action="store_const", const=RESTART, help="restart session")

    parser.add_argument("-i", "--id", dest="subsId",
            help="subscriber id default imsi out of testing")

    parser.add_argument("-t", "--id-type", dest="subsType",
            choices=["imsi", "imei"],
            help="subscriber id type { IMSI, IMEI }")

    parser.add_argument("-f", "--framed-ip", dest="framedIp",
            help="framed ip")

    parser.add_argument("-v", "--verbose", dest="verbose",
            action="store_true", help="enable verbose output")


    args = parser.parse_args()
    data.__dict__.update(args.__dict__)
    return data



class RadiusAvp(object):
    def __init__(self, avpType, avpValue, allowChild=True):
        self.avpType = AVP_TYPE[avpType]
        self.avpValue = avpValue
        self.vsaChild = None

        if allowChild and avpType.startswith("3GPP"):
            self.avpType = 26                   # Vendor_Specific
            self.avpValue = IntegerType(10415)  # 3GPP
            self.vsaChild = RadiusAvp(avpType, avpValue, False)
            self.avpLength = 6 + self.vsaChild.avpLength
        else:
            self.avpLength = 2 + len(avpValue)


    def dump(self):
        value = struct.pack(RADIUS_AVP_TMPL % len(self.avpValue),
                self.avpType,
                self.avpLength,
                self.avpValue.dump())

        if self.vsaChild:
            return "".join((value, self.vsaChild.dump()))

        return value


    def __len__(self):
        return self.avpLength


    def __str__(self):
        avp = "AVP: Type:{%d}  Length:{%d}  Value:{%s}\n" % (self.avpType,
                self.avpLength, str(self.avpValue))
        if self.vsaChild:
            avp = "".join((avp, " >> %s" % str(self.vsaChild)))
        return avp



class RadiusAcctRequest(object):
    """Radius accounting request object"""
    def __init__(self, secret):
        self.code = 4
        self.pid = 0xf5
        self.length = 20    # length so far
        self.auth = hashlib.md5(secret)
        self.avpList = []


    def addAVP(self, avp):
        if avp and isinstance(avp, RadiusAvp):
            self.avpList.append(avp)
            self.length += avp.avpLength


    def dump(self):
        """dump binary version of the Radius Request packet payload
        including AVPs"""
        avps = "".join([avp.dump() for avp in self.avpList])
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                self.length,
                self.auth.digest())
        return "".join([header, avps])


    def __len__(self):
        return self.length


    def __str__(self):
        header = "HEADER:\nCode:{%d}  PID{%d}  Length:{%d}  Auth{%s}\n" % (self.code,
                self.pid, self.length, self.auth.hexdigest())
        avps = "".join([str(avp) for avp in self.avpList])
        return "".join((header, avps))



class AddressType(object):
    """IP address data type"""
    def __init__(self, addr, ipv6=False):
        assert(type(addr) == str)
        self.addr = addr.strip()
        if ipv6:
            raise NotImplementedError()

    def __str__(self):
        return self.addr

    def __len__(self):
        return 4

    def dump(self):
        octets = [int(i) for i in self.addr.split(".")]
        if (len(octets) != 4):
            raise ValueError("Invalid IP address format")
        return struct.pack("!BBBB", *octets)


class TextType(object):
    """Text data type"""
    def __init__(self, value):
        assert(type(value) == str)
        self.value = value
        if len(self.value) == 0:
            raise ValueError("Empty strings are not allowed (rfc2866)")

    def __len__(self):
        return len(self.value)

    def __str__(self):
        return self.value

    def dump(self):
        return struct.pack("!%ss" % len(self.value), self.value)


class IntegerType(object):
    """Integer data type"""
    def __init__(self, value, length=1):
        """length is set in 4byte chunks. eg. length = 4 == 16bytes"""
        assert(type(value) == int)
        self.value = value
        self.length = length

    def __len__(self):
        length = len(hex(self.value))-2
        length += length % 2
        return max(4, length / 2)

    def __str__(self):
        return str(self.value)

    def dump(self):
        values = [self.value >> (n*32) & 0xffffffff for n in range(self.length)]
        values.reverse()
        return struct.pack("!%dL" % self.length, *values)


def createPacket(data):
    """generate a binary version of the packet based on the current data"""
    rad = RadiusAcctRequest(data.radiusSecret)
    rad.addAVP(RadiusAvp("Acct_Status_Type", IntegerType(data.action)))
    rad.addAVP(RadiusAvp("NAS_IP_Addr", AddressType(data.radiusDest)))
    rad.addAVP(RadiusAvp("Framed_IP_Addr", AddressType(data.framedIp)))
    if data.subsType == "imsi":
        rad.addAVP(RadiusAvp("3GPP_IMSI", TextType(data.subsId)))
    elif data.subsType == "imei":
        rad.addAVP(RadiusAvp("3GPP_IMEISV", TextType(data.subsId)))
    else:
        raise ValueError("Unknown type of subscriber identifier")

    if data.verbose:
        print str(rad)
    return bytes(rad.dump())


def sendPacket(destTuple, packet):
    """send the packet to the network"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
    sock.sendto(packet, destTuple)
    sock.close()


def startStopSession(data):
    """send start/stop session based on action in the data"""
    sendPacket((data.radiusDest, data.radiusPort), createPacket(data))


def restartSession(data, timeout=1):
    """restart session
    1. stop the current session
    2. wait for <timeout>
    3. start the new session with the given data
    """
    import time
    data.action = STOP
    startStopSession(data)
    time.sleep(timeout)
    data.action = START
    startStopSession(data)


if __name__ == "__main__":
    data = parseArgs(Data())
    strAction = ["Restarting", "Starting", "Stoping"]
    if data.verbose:
        print "%s the session" % strAction[data.action]

    if data.action == RESTART:
        restartSession(data)
    else:
        startStopSession(data)


# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
