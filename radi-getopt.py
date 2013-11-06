#!/usr/bin/env python
#
# radi-getopt.py
# Author: Aleksei Kozadaev (2013)
#

import getopt, sys
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
    "User-Name" : 1,
    "NAS-IP-Address" : 4,
    "Framed-Protocol" : 7,
    "Framed-IP-Address" : 8,
    "Framed-IP-Netmask" : 9,
    "Vendor_Specific" : 26,
    "Called-Station-Id" : 30,
    "Calling-Station-Id" : 31,
    "Acct-Status-Type" : 40,
    "NAS-IPv6-Address" : 95,
    "Framed-IPv6-Prefix" : 97,

    # Vendor specific (26)
    "3GPP-IMSI" : 1,
    "3GPP-IMEISV" : 20,
    "3GPP-User-Location-Info" : 22
}


# Constants
FRAMED_PROTO_PPP = 1
PICKLED_FILE_NAME = "./.%s.dat" % __file__

class Config(object):
    """config storage object"""
    def __init__(self):
        self.radius_dest = "127.0.0.1"
        self.radius_port = 1813
        self.radius_secret = "secret"
        self.username = "johndoe"
        self.subs_id = "12345678901234"
        self.subs_type = "imsi"
        self.framed_ip ="10.0.0.1"
        self.framed_mask = 32
        self.calling_id = "00441234987654"
        self.called_id = "web.apn"
        self.subs_loc_info = struct.pack("!BBBBHH",
                1,      # Location Type (SAI (1))
                0x62,   # 2 octets MCC (Germany (262))
                0x02,   # 1 octet MCC / 1 MNC
                0x10,   # 2 octets MNC (T-Mobile (10))
                0xffff, # LAC
                0xffff) # CI
        self.delay = 1
        self.action = START
        self.verbose = False


    def update(self, config):
        """merge the current object with 'config' dictionary"""
        self.__dict__.update(config)



class RadiusAvp(object):
    """Radius avp implementations"""
    def __init__(self, avp_type, avp_value, allow_child=True):
        self.vsa_child = None
        self.avp_type = AVP_TYPE[avp_type]
        if allow_child and avp_type.startswith("3GPP"):
            self.avp_type = 26                   # Vendor_Specific
            self.avp_value = IntegerType(10415)  # 3GPP
            self.vsa_child = RadiusAvp(avp_type, avp_value, False)
            self.avp_length = 6 + len(self.vsa_child)
        else:
            self.avp_value = avp_value
            self.avp_length = 2 + len(self.avp_value)


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
        return self.avp_length


    def __str__(self):
        avp = "AVP: Type:{%d}  Length:{%d}  Value:{%s}\n" % (
                self.avp_type,
                len(self),
                str(self.avp_value))
        if self.vsa_child:
                return "".join((avp, "`- %s" % str(self.vsa_child)))
        return avp



class RadiusAcctRequest(object):
    """Radius accounting request object"""
    def __init__(self, secret):
        self.code = 4
        self.pid = 0xf5
        self.length = 20    # length so far
        self.auth = IntegerType(0, length=4)
        self.secret = secret
        self.avp_list = []


    def add_avp(self, avp):
        """add an AVP class to the list of the packets AVPs"""
        if avp and isinstance(avp, RadiusAvp):
            self.avp_list.append(avp)
            self.length += len(avp)


    def compute_authenticator(self):
        """compute authetnicator of the radius request"""
        self.auth = IntegerType(0, length=4)
        avps = "".join([avp.dump() for avp in self.avp_list])
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                len(self),
                bytes(self.auth))
        packet = "".join([header, avps, self.secret])
        self.auth = hashlib.md5(packet).digest()


    def dump(self):
        """dump binary version of the Radius Request packet payload
        including AVPs"""
        self.compute_authenticator()
        avps = "".join([avp.dump() for avp in self.avp_list])
        header = struct.pack(RADIUS_HDR_TMPL,
                self.code,
                self.pid,
                len(self),
                self.auth)
        return "".join([header, avps])


    def __len__(self):
        return self.length


    def __str__(self):
        self.compute_authenticator()
        header = "HEADER:  Code:{%d}  PID{%d}  Length:{%d}  Auth{%s}\n" % (
                self.code, self.pid, len(self), self.auth.encode("hex"))
        avps = "".join([str(avp) for avp in self.avp_list])
        return "".join((header, avps))



class AddressType(object):
    """IP ip_string data type"""
    def __init__(self, ip_string, is_ipv6=False):
        if type(ip_string) != str:
            raise ValueError("String expected")

        self.family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        self.ip_string = ip_string

        try:
            self.bin_ip_string = socket.inet_pton(self.family, ip_string)
        except socket.error:
            raise ValueError("Invalid IP ip_string")


    def __str__(self):
        return self.ip_string


    def __len__(self):
        return len(self.bin_ip_string)


    def dump(self):
        return bytes(self.bin_ip_string)



class TextType(object):
    """Text data type"""
    def __init__(self, value):
        if not value:
            raise ValueError("Empty strings are not allowed (rfc2866)")
        if type(value) != str:
            raise ValueError("String expected")
        self.value = value


    def __len__(self):
        return len(self.value)


    def __str__(self):
        return str(self.value)


    def dump(self):
        return struct.pack("!%ss" % len(self.value), self.value)



class IntegerType(object):
    """Integer data type"""
    def __init__(self, value, length=1):
        """length is set in 4byte chunks. eg. length = 4 == 16bytes"""
        if type(value) != int:
            raise ValueError("Integer expected")
        self.value = value
        self.length = length


    def __len__(self):
        return self.length * 4


    def __str__(self):
        return str(self.value)


    def dump(self):
        values = [self.value >> (n*32) & 0xffffffff
                for n in range(self.length-1, -1, -1)]
        return struct.pack("!%dL" % len(values), *values)



class ByteType(object):
    """Byte data type"""
    def __init__(self, value):
        if type(value) != int:
            raise ValueError("Integer expected")
        if value < 0 or value > 0xff:
            raise ValueError("byte - type overflow")
        self.value = value


    def __len__(self):
        return 1


    def __str__(self):
        return str(self.value)


    def dump(self):
        """dump binary value"""
        return struct.pack("!B", self.value)



class ContainerType(object):
    """Container type allowing to join several values togeter"""
    def __init__(self, *args):
        self.values = args


    def __len__(self):
        return sum([len(value) for value in self.values])


    def __str__(self):
        return "".join([str(value) for value in self.values])


    def dump(self):
        """dump binary representaton of the contained values"""
        values_binary = "".join([value.dump() for value in self.values])
        return bytes(values_binary)


def is_ipv6(address):
    """returns true if the IP is IPv6"""
    return (":" in address)


def create_packet(config):
    """generate a binary version of the packet based on the current config"""
    rad = RadiusAcctRequest(config.radius_secret)
    rad.add_avp(RadiusAvp("User-Name", TextType(config.username)))
    rad.add_avp(RadiusAvp("Acct-Status-Type", IntegerType(config.action)))

    if is_ipv6(config.radius_dest):
        rad.add_avp(RadiusAvp("NAS-IPv6-Address",
            AddressType(config.radius_dest, True)))
    else:
        rad.add_avp(RadiusAvp("NAS-IP-Address",
            AddressType(config.radius_dest)))

    if is_ipv6(config.framed_ip):
        rad.add_avp(RadiusAvp("Framed-IPv6-Prefix",
            ContainerType(
                ByteType(0),
                ByteType(config.framed_mask),
                AddressType(config.framed_ip, True))))
    else:
        rad.add_avp(RadiusAvp("Framed-IP-Address",
            AddressType(config.framed_ip)))
        rad.add_avp(RadiusAvp("Framed-IP-Netmask",
            AddressType(bits_to_ip4mask(config.framed_mask))))

    rad.add_avp(RadiusAvp("Framed-Protocol", IntegerType(FRAMED_PROTO_PPP)))
    rad.add_avp(RadiusAvp("Calling-Station-Id", TextType(config.calling_id)))
    rad.add_avp(RadiusAvp("Called-Station-Id", TextType(config.called_id)))

    rad.add_avp(RadiusAvp("3GPP-User-Location-Info",
        TextType(config.subs_loc_info)))

    if config.subs_type == "imsi":
        rad.add_avp(RadiusAvp("3GPP-IMSI", TextType(config.subs_id)))
    elif config.subs_type == "imei":
        rad.add_avp(RadiusAvp("3GPP-IMEISV", TextType(config.subs_id)))
    else:
        raise ValueError("Unknown type of subscriber identifier")

    debug(str(rad))

    return bytes(rad.dump())


def bits_to_ip4mask(num_bits):
    """convert integer number of bits in ipv4 netmask to string representation
    of the mask. Eg. '255.255.255.0'"""
    if 0 <= num_bits <= 32:
        bits = 0xffffffff ^ ((1 << (32 - num_bits)) - 1)
        ip4_bytes = [str((bits >> 8*n) & 0xff) for n in range(3, -1, -1)]
        return ".".join(ip4_bytes)
    else:
        raise ValueError("invalid IPv4 mask specified")


def send_packet(destTuple, packet):
    """send the packet to the network"""
    if is_ipv6(destTuple[0]):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 20)
    else:
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
    time.sleep(float(config.delay))
    config.action = START
    start_stop_session(config)


def usage():
    print("Radius accounting session management tool\n\n"
        "usage: radi.py [-h] [-d RADIUS_DEST] [-p RADIUS_SECRET]"
        " [-S | -T | -R]\n"
        "               [-i SUBS_ID] [-t {imsi,imei}] [-f FRAMED_IP]"
        " [-c CALLING_ID]\n"
        "               [-C CALLED_ID] [-D DELAY] [-L] [-v]\n\n"
        "optional arguments:\n"
        "  -h, --help            show this help message and exit\n"
        "  -d RADIUS_DEST, --destination RADIUS_DEST\n"
        "                        ip of radius endpoint\n"
        "  -p RADIUS_SECRET, --secret RADIUS_SECRET\n"
        "                        radius secret\n"
        "  -S, --start           Start session\n"
        "  -T, --stop            Stop session\n"
        "  -R, --restart         Restart session\n"
        "  -i SUBS_ID, --id SUBS_ID\n"
        "                        subscriber id { default imsi }\n"
        "  -t {imsi,imei}, --id-type {imsi,imei}\n"
        "                        subscriber id type { IMSI, IMEI }\n"
        "  -f FRAMED_IP, --framed-ip FRAMED_IP\n"
        "                        framed ip\n"
        "  -c CALLING_ID, --calling-id CALLING_ID\n"
        "                        3GPP calling id\n"
        "  -C CALLED_ID, --called-id CALLED_ID\n"
        "                        3GPP called id\n"
        "  -D, --delay DELAY     the delay between stopping and starting"
        " the session\n"
        "                        during the restart mode (-R/--restart)\n"
        "  -L, --clean           clean the cached configuration\n"
        "  -v, --verbose         enable verbose output\n")


def parse_args():
    """parse CLI arguments"""
    config = dict()
    config["name"] = sys.argv.pop(0)
    try:
        opt_list, arg_list = getopt.getopt(sys.argv, "hd:p:STRi:t:f:c:C:D:Lv",
                ["help", "destination", "secret", "start", "stop", "restart",
                "id", "id-type", "framed-ip", "calling-id", "called_id",
                "delay", "clean", "verbose"])
    except getopt.GetoptError as err:
        usage()
        print "\n%s" % str(err)
        sys.exit(2)

    for opt, value in opt_list:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif opt in ("-d", "--destination"):
            config["radius_dest"] = value
        elif opt in ("-p", "--secret"):
            config["radius_secret"] = value
        elif opt in ("-S", "--start"):
            config["action"] = START
        elif opt in ("-T", "--stop"):
            config["action"] = STOP
        elif opt in ("-R", "--restart"):
            config["action"] = RESTART
        elif opt in ("-i", "--id"):
            config["subs_id"] = value
        elif opt in ("-t", "--id-type"):
            if value.lower() in ("imsi", "imei"):
                config["subs_type"] = value.lower()
            else:
                raise ValueError("invalid id-type value")
        elif opt in ("-f", "--framed-ip"):
            if "/" in value:
                value, mask = value.split("/")
                if mask.isdigit():
                    config["framed_mask"] = min(int(mask), 128)
            config["framed_ip"] = value
        elif opt in ("-c", "--calling-id"):
            config["calling_id"] = value
        elif opt in ("-C", "--called-id"):
            config["called_id"] = value
        elif opt in ("-D", "--delay"):
            config["delay"] = value
        elif opt in ("-L", "--clean"):
            config["cleancache"] = True
        elif opt in ("-v", "--verbose"):
            config["verbose"] = True

    return config


def debug(message, force=False):
    """debug output - printed only if the verbose config option is set"""
    if config.verbose or force:
        print message


def main(config):
    # reading the event arguments
    args = parse_args()

    # try loading the pickled configuration
    if not "cleancache" in args:
        try:
            with open(PICKLED_FILE_NAME, "r") as f:
                cache = pickle.load(f)
            config.update(cache.__dict__)
            if "verbose" in args:
                debug("Cache found. Loading...", force=True)
        except IOError:
            cache = None

    config.update(args)     # merging configuration
    action_strings = ["Restarting", "Starting", "Stoping"]

    debug("%s the session" % action_strings[config.action])

    if config.action == RESTART:
        restart_session(config)
    else:
        start_stop_session(config)

    # pickling the current configuration for future reuse
    debug("Caching the current config for future use")
    with open(PICKLED_FILE_NAME, "w") as f:
        pickle.dump(config, f)


if __name__ == "__main__":
    config = Config()

    try:
        main(config)        # main logic
    except (ValueError, NotImplementedError, IOError) as e:
        print "ERROR: %s" % e.message

# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
