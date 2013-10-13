#!/usr/bin/env python
#
# radi.py
# Author: Aleksei Kozadaev
#

import argparse
import struct, socket
import pickle, hashlib

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

# Constants
FRAMED_PROTO_PPP = 1
PICKLED_FILE_NAME = "radi.dat"

class Config(object):
    """config storage object"""
    def __init__(self):
        self.radius_dest = "127.0.0.1"
        self.radius_port = 1813
        self.radius_secret = "secret"
        self.verbose = False
        self.subs_id = "12345678901234"
        self.subs_type = "imsi"
        self.framed_ip ="10.0.0.1"
        self.delay = 1
        self.action = START
        self.verbose = False



class RadiusAvp(object):
    """simple radius AVP implementation"""
    def __init__(self, avp_type, avp_value, allow_child=True):
        self.avp_type = AVP_TYPE[avp_type]
        self.avp_value = avp_value
        self.vsa_child = None

        if allow_child and avp_type.startswith("3GPP"):
            self.avp_type = 26                   # Vendor_Specific
            self.avp_value = IntegerType(10415)  # 3GPP
            self.vsa_child = RadiusAvp(avp_type, avp_value, False)
            self.avp_length = 6 + len(self.vsa_child)
        else:
            self.avp_length = 2 + len(avp_value)


    def dump(self):
        """dump the binary representation of the AVP"""
        value = struct.pack(RADIUS_AVP_TMPL % len(self.avp_value),
                self.avp_type,
                self.avp_length,
                self.avp_value.dump())

        if self.vsa_child:
            return "".join((value, self.vsa_child.dump()))

        return value


    def __len__(self):
        return self.avp_length


    def __str__(self):
        avp = "AVP: Type:{%d}  Length:{%d}  Value:{%s}\n" % (self.avp_type,
                self.avp_length, str(self.avp_value))
        if self.vsa_child:
            avp = "".join((avp, "`- %s" % str(self.vsa_child)))
        return avp



class RadiusAcctRequest(object):
    """Radius accounting request object"""
    def __init__(self, secret):
        self.code = 4
        self.pid = 0xf5
        self.length = 20    # length so far
        self.auth = hashlib.md5(secret)
        self.avp_list = []


    def add_avp(self, avp):
        if avp and isinstance(avp, RadiusAvp):
            self.avp_list.append(avp)
            self.length += avp.avp_length


    def dump(self):
        """dump binary version of the Radius Request packet payload including
        AVPs"""
        avps = "".join([avp.dump() for avp in self.avp_list])
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                self.length,
                self.auth.digest())
        return "".join([header, avps])


    def __len__(self):
        return self.length


    def __str__(self):
        header = "HEADER:  Code:{%d}  PID{%d}  Length:{%d}  Auth{%s}\n" % (
                self.code, self.pid, self.length, self.auth.hexdigest())
        avps = "".join([str(avp) for avp in self.avp_list])
        return "".join((header, avps))



class AddressType(object):
    """IP address data type"""
    def __init__(self, addr, ipv6=False):
        assert(type(addr) == str)
        self.addr = addr.strip()
        if ipv6:
            raise NotImplementedError("IPv6 not yet supported")

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
        if not self.value:
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



def create_packet(config):
    """generate a binary version of the packet based on the current config"""
    rad = RadiusAcctRequest(config.radius_secret)
    rad.add_avp(RadiusAvp("Acct_Status_Type", IntegerType(config.action)))
    rad.add_avp(RadiusAvp("NAS_IP_Addr", AddressType(config.radius_dest)))
    rad.add_avp(RadiusAvp("Framed_IP_Addr", AddressType(config.framed_ip)))
    rad.add_avp(RadiusAvp("Framed_Protocol", IntegerType(FRAMED_PROTO_PPP)))
    if config.subs_type == "imsi":
        rad.add_avp(RadiusAvp("3GPP_IMSI", TextType(config.subs_id)))
    elif config.subs_type == "imei":
        rad.add_avp(RadiusAvp("3GPP_IMEISV", TextType(config.subs_id)))
    else:
        raise ValueError("Unknown type of subscriber identifier")

    debug(str(rad))

    return bytes(rad.dump())


def send_packet(destTuple, packet):
    """send the packet to the network"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
    sock.sendto(packet, destTuple)
    sock.close()


def start_stop_session(config):
    """send start/stop session based on action in the config"""
    send_packet((config.radius_dest, config.radius_port), create_packet(config))


def restart_session(config):
    """restart session
    1. stop the current session
    2. wait for <delay>
    3. start the new session with the given config
    """
    import time
    config.action = STOP
    start_stop_session(config)
    time.sleep(config.delay)
    config.action = START
    start_stop_session(config)


def parse_args(config):
    """parse CLI arguments"""
    parser = argparse.ArgumentParser(
            description="Radius accounting session management tool",
            argument_default=argparse.SUPPRESS)

    parser.add_argument("-d", "--destination", dest="radius_dest",
            help="ip of radius endpoint", required=False)

    parser.add_argument("-p", "--secret", dest="radius_secret",
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

    parser.add_argument("-i", "--id", dest="subs_id",
            help="subscriber id default imsi out of testing")

    parser.add_argument("-t", "--id-type", dest="subs_type",
            choices=["imsi", "imei"],
            help="subscriber id type { IMSI, IMEI }")

    parser.add_argument("-f", "--framed-ip", dest="framed_ip",
            help="framed ip")

    parser.add_argument("-v", "--verbose", dest="verbose",
            action="store_true", default=False,
            help="enable verbose output")

    parser.add_argument("--delay", dest="delay", default="1",
            help="""the delay between stopping and starting the session
            during the restart mode (-R/--restart)""")

    args = parser.parse_args()
    config.__dict__.update(args.__dict__)
    return config


def debug(message):
    """debug output - printed only if the verbose config option is set"""
    if config.verbose:
        print message


def main(config):
    """main logic"""
    action_strings = ["Restarting", "Starting", "Stoping"]

    debug("%s the session" % action_strings[config.action])

    if config.action == RESTART:
        restart_session(config)
    else:
        start_stop_session(config)


if __name__ == "__main__":
    config = Config()
    use_cached = False

    # try loading the pickled configuration
    try:
        with open(PICKLED_FILE_NAME, "r") as f:
            config = pickle.load(f)
            use_cached = True
    except IOError:
        pass

    # reading the event arguments and merging with the config
    config = parse_args(config)

    if use_cached:
        debug("Cached config found. Loading...")

    try:
        main(config)      # main logic
    except (ValueError, NotImplementedError) as e:
        print "ERROR: %s" % s.message

    # pickling the current configuration for future reuse
    debug("Caching the current config for future use")
    with open(PICKLED_FILE_NAME, "w") as f:
        pickle.dump(config, f)

# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
