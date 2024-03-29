#!/usr/bin/env python
#
# radi.py
# Author: Aleksei Kozadaev (2013)
#

import sys
import getopt
import os.path
import struct
import pickle

import libradi
from version import __version__

# Globals
__verbose__ = False  # enabling verbose logging

# Constants
RESTART, START, STOP, INTERIM = range(4)  # also ACCT_STATUS_TYPE start/stop
FRAMED_PROTO_PPP = 1
PICKLED_FILE_NAME = f"{os.path.curdir}/.{os.path.basename(__file__)}.dat"


class Config:
    """config storage object"""

    def __init__(self):
        load_install_path()
        self.dict_path = os.path.join(INSTALL_PREFIX, "dict")
        self.dict_fname = "dictionary"
        self.radius_dest = "127.0.0.1"
        self.radius_port = 1813
        self.radius_secret = "secret"
        self.username = "johndoe"
        self.imsi = "12345678901234"
        self.imei = "3456789012345678901234567890"
        self.framed_ip = "10.0.0.1"
        self.framed_mask = None
        self.calling_id = "00441234987654"
        self.called_id = "web.apn"
        self.subs_loc_info = struct.pack(
            "!BBBBHH",
            1,  # Location Type (SAI (1))
            0x62,  # 2 octets MCC (Germany (262))
            0x02,  # 1 octet MCC / 1 MNC
            0x10,  # 2 octets MNC (T-Mobile (10))
            0xffff,  # LAC
            0xffff)  # CI
        self.delay = 1
        self.action = START

        self.avps = []

    def update(self, config):
        """merge the current object with 'config' dictionary"""
        self.__dict__.update(config)


def load_install_path():
    global INSTALL_PREFIX
    try:
        import libradi.config
        INSTALL_PREFIX = os.path.join(libradi.config.install_pfx,
                                      "share/libradi")
        del libradi.config
    except ImportError:
        INSTALL_PREFIX = ""


def is_ipv6(ipaddr):
    return ":" in ipaddr


def create_radius_request(config, action):
    """generate a binary version of the packet based on the current config"""
    rad = libradi.RadiusMessage(config.radius_secret)
    rad.add_avp(libradi.RadiusAvp("User-Name", config.username))
    rad.add_avp(libradi.RadiusAvp("Acct-Status-Type", action))

    if is_ipv6(config.radius_dest):
        rad.add_avp(libradi.RadiusAvp("NAS-IPv6-Address", config.radius_dest))
    else:
        rad.add_avp(libradi.RadiusAvp("NAS-IP-Address", config.radius_dest))

    if is_ipv6(config.framed_ip):
        if not config.framed_mask:
            config.framed_mask = 128
        rad.add_avp(
            libradi.RadiusAvp("Framed-IPv6-Prefix",
                              f"{config.framed_ip}/{config.framed_mask}"))
    else:
        if not config.framed_mask:
            config.framed_mask = 32
        rad.add_avp(libradi.RadiusAvp("Framed-IP-Address", config.framed_ip))
        rad.add_avp(
            libradi.RadiusAvp(
                "Framed-IP-Netmask",
                libradi.radtypes.bits_to_ip4mask(config.framed_mask)))

    rad.add_avp(libradi.RadiusAvp("Framed-Protocol", FRAMED_PROTO_PPP))
    rad.add_avp(libradi.RadiusAvp("Calling-Station-Id", config.calling_id))
    rad.add_avp(libradi.RadiusAvp("Called-Station-Id", config.called_id))

    rad.add_avp(
        libradi.RadiusAvp("3GPP-Location-Info",
                          "0x" + config.subs_loc_info.hex()))

    rad.add_avp(libradi.RadiusAvp("3GPP-IMSI", config.imsi))
    rad.add_avp(libradi.RadiusAvp("3GPP-IMEISV", config.imei))

    for name, value in config.avps:
        rad.add_avp(libradi.RadiusAvp(name, value))

    # debug(str(rad))

    return rad


def change_session(conifg, action):
    """send start/stop session based on action in the config"""
    create_radius_request(config, action).send(
        (config.radius_dest, config.radius_port))


def restart_session(config):
    """restart session
    1. stop the current session
    2. wait for <delay>
    3. start the new session with the given config
    """
    import time
    change_session(config, STOP)
    time.sleep(float(config.delay))
    change_session(config, START)


def usage():
    print("Radius accounting session management tool {}\n\n"
          "usage: radi.py [-h] [-d RADIUS_DEST] [-p RADIUS_SECRET]"
          " [-S | -T | -R]\n"
          "               [-i SUBS_ID] [-t {{imsi,imei}}] [-f FRAMED_IP]"
          " [-c CALLING_ID]\n"
          "               [-C CALLED_ID] [-D DELAY] [-L] [-v]\n\n"
          "optional arguments:\n"
          "  -h, --help            show this help message and exit\n"
          "  -d RADIUS_DEST, --destination RADIUS_DEST\n"
          "                        ip of radius endpoint\n"
          "  -p RADIUS_SECRET, --secret RADIUS_SECRET\n"
          "                        radius secret\n"
          "  -S, --start           start session\n"
          "  -T, --stop            stop session\n"
          "  -I, --interim         send interim update\n"
          "  -R, --restart         restart session\n"
          "  -u, --username        username\n"
          "  -i IMSI, --imsi IMSI  subscriber imsi\n"
          "  -t IMEI, --imei IMEI  subscriber imei\n"
          "  -f FRAMED_IP, --framed-ip FRAMED_IP\n"
          "                        framed ip\n"
          "  -c CALLING_ID, --calling-id CALLING_ID\n"
          "                        3GPP calling id\n"
          "  -C CALLED_ID, --called-id CALLED_ID\n"
          "                        3GPP called id\n"
          "  -a, --avp NAME=VALUE  add an avp (can be repeated "
          "multiple times)\n"
          "  -D, --delay DELAY     the delay between stopping and starting\n"
          "                        the session in the restart mode "
          "(-R/--restart)\n"
          "  -L, --clean           clean the cached configuration\n"
          "  -P, --path <path to dictionary>\n"
          "                        path to the dictionary files\n"
          "  -v, --verbose         enable verbose output\n\n"
          "Accepted types: {}\n\n"
          "PLEASE NOTE:\n"
          " - If action is specified multiple times, the last one\n"
          "   will be used. Eg. -S -R -T will run the session\n"
          "   stop (-T/--stop).\n\n"
          " - The date type should be a unix time stamp (seconds since\n"
          "   1970-01-01 00:00:00 UTC).\n"
          "   Eg. -a event-timestamp=1234567890.123456\n\n"
          " - TLV type should be formated as follows:\n"
          "   <type>/<value>\n"
          "   type - (1 byte - dec or hex)\n"
          "   value - any number of bytes - dec or hex value\n\n".format(
              __version__, ",".join(libradi.radtypes.get_supported_types())))


def parse_avp(value):
    """parse avpname=avpvalue pair to a tuple"""
    try:
        name, value = value.split("=")
    except ValueError:
        raise ValueError("invalid avp format")
    assert (name is not None and value is not None)
    return (name, value)


def parse_args():
    """parse CLI arguments"""
    global __verbose__
    config = dict()
    config["name"] = sys.argv.pop(0)
    try:
        opt_list, arg_list = getopt.getopt(
            sys.argv, "hd:u:p:STIRi:t:f:c:C:a:D:LP:v", [
                "help", "destination=", "user=", "secret=", "start", "stop",
                "interim", "restart", "imsi=", "imei=", "framed-ip=",
                "calling-id=", "called_id=", "avp=", "delay=", "clean",
                "path=", "verbose"
            ])
    except getopt.GetoptError as err:
        usage()
        print(f"\n{str(err)}")
        sys.exit(2)

    for opt, value in opt_list:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif opt in ("-d", "--destination"):
            config["radius_dest"] = value
        elif opt in ("-u", "--username"):
            config["username"] = value
        elif opt in ("-p", "--secret"):
            config["radius_secret"] = value
        elif opt in ("-S", "--start"):
            config["action"] = START
        elif opt in ("-T", "--stop"):
            config["action"] = STOP
        elif opt in ("-R", "--restart"):
            config["action"] = RESTART
        elif opt in ("-I", "--interim"):
            config["action"] = INTERIM
        elif opt in ("-i", "--imsi"):
            config["imsi"] = value
        elif opt in ("-t", "--imei"):
            config["imei"] = value
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
        elif opt in ("-a", "--avp"):
            config.setdefault("avps", []).append(parse_avp(value))
        elif opt in ("-D", "--delay"):
            config["delay"] = value
        elif opt in ("-L", "--clean"):
            config["cleancache"] = True
        elif opt in ("-P", "--path"):
            config["dict_path"] = value
        elif opt in ("-v", "--verbose"):
            __verbose__ = True

    return config


def debug(message, force=False):
    """debug output - printed only if the verbose config option is set"""
    global __verbose__
    if __verbose__ or force:
        print(message)


def main(config):
    # reading the event arguments
    args = parse_args()

    # try loading the pickled configuration
    if "cleancache" not in args:
        try:
            with open(PICKLED_FILE_NAME, "rb") as f:
                cache = pickle.load(f)
            if "verbose" in args:
                debug("Cache found. Loading...", force=True)
            config.update(cache.__dict__)
        except IOError:
            cache = None

    config.update(args)  # merging configuration
    action_strings = ["Restarting", "Starting", "Stoping", "Updating"]

    debug("%s the session" % action_strings[config.action])
    libradi.dictionary.initialize(config.dict_path, config.dict_fname)

    if config.action == RESTART:
        restart_session(config)
    else:
        change_session(config, config.action)

    # pickling the current configuration for future reuse
    debug("Caching the current config for future use")
    with open(PICKLED_FILE_NAME, "wb") as f:
        pickle.dump(config, f)


if __name__ == "__main__":
    config = Config()

    try:
        main(config)  # main logic
    except (KeyboardInterrupt):
        print("Interrupted... Exiting")
        sys.exit(1)
    except (ValueError, IOError) as e:
        print(f"ERROR: {e.message}")
    except (NotImplementedError) as e:
        print(f"Not Implemented: {e.message}")
