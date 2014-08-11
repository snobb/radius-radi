#!/usr/bin/env python
#
# radtypes.py
# Author: Alex Kozadaev (2014)
#

import struct
import socket


class AbstractType(object):
    """Abstract Type interface"""
    def __init__(self, value, length = None):
        self.value = value
        self.length = length

    def __len__(self):
        return length if length else len(value)

    def __lt__(self, other):
        if type(self) != type(other):
            raise AttributeError("Incomparable types")
        return self.value < other.value

    def __le__(self, other):
        if type(self) != type(other):
            raise AttributeError("Incomparable types")
        return self.value <= other.value

    def __eq__(self, other):
        if type(self) != type(other):
            raise AttributeError("Incomparable types")
        return self.value == other.value

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        if type(self) != type(other):
            raise AttributeError("Incomparable types")
        return self.value > other.value

    def __ge__(self, other):
        if type(self) != type(other):
            raise AttributeError("Incomparable types")
        return self.value >= other.value

    def __str__(self):
        return str(self.value)

    def __dump__(self):
        raise NotImplementedError()


class AddressType(AbstractType):
    """IP ip_string data type"""
    def __init__(self, value):
        super(AddressType, self).__init__(str(value))

        self.family = socket.AF_INET6 if self.is_ipv6() else socket.AF_INET

        try:
            self.bin_ip_string = socket.inet_pton(self.family, value)
        except socket.error:
            raise ValueError("Invalid IP ip_string")

    def is_ipv6(self):
        return (":" in self.value)

    def __str__(self):
        return self.value

    def __len__(self):
        return len(self.bin_ip_string)

    def dump(self):
        return bytes(self.bin_ip_string)


class AddressIPv6PrefixType(AbstractType):
    """IP ip_string data type"""
    def __init__(self, value, mask=None):
        super(AddressIPv6PrefixType, self).__init__(str(value))

        if not self.is_ipv6():
            raise ValueError("Invalid input: {}".format(value))

        self.family = socket.AF_INET6

        if mask:
            self.ipv6addr, self.mask = value, min(int(mask), 128)
        else:
            if "/" in value:
                self.ipv6addr, self.mask = value.split("/")
                self.mask = min(int(self.mask), 128)
            else:
                self.ipv6addr, self.mask = value, 128

        try:
            self.bin_ip_string = socket.inet_pton(self.family, self.ipv6addr)
        except socket.error:
            raise ValueError("Invalid IPv6 prefix: {}".format(self.ipv6addr))

    def is_ipv6(self):
        return (":" in self.value)

    def __str__(self):
        return self.value

    def __len__(self):
        return len(self.bin_ip_string)+2

    def dump(self):
        short = ShortType(self.mask)
        return "".join((ShortType(self.mask).dump(), self.bin_ip_string))


class TextType(AbstractType):
    """Text data type"""
    def __init__(self, value):
        super(TextType, self).__init__(str(value))
        if not value:
            raise ValueError("Empty strings are not allowed (rfc2866)")

    def __len__(self):
        return len(self.value)

    def __str__(self):
        return str(self.value)

    def dump(self):
        return struct.pack("!%ss" % len(self.value), self.value)


class NumericBaseType(AbstractType):
    """Integer data type"""
    def __init__(self, value, length=1):
        """the class MUST be overrided and set byte_length and pattern"""
        if type(value) == str:
            if "x" in value:
                self.value = int(value, 16)
            else:
                self.value = int(value)
        else:
            self.value = value

        assert(type(self.value) == long or type(self.value) == int)
        assert(0 <= self.value)
        self.byte_length = None # chunk length in bytes
        self.pattern = None     # struct pattern
        self.length = length

    def __len__(self):
        return self.length * self.byte_length

    def __str__(self):
        return str(self.value)

    def dump(self):
        assert(type(self.value) == long or type(self.value) == int)
        bit_len = self.byte_length * 8
        mask = (1 << bit_len)-1
        values = [self.value >> (n*bit_len) & mask
                for n in range(self.length-1, -1, -1)]
        return struct.pack("!{}{}".format(len(values),self.pattern), *values)


class IntegerType(NumericBaseType):
    """Integer data type"""
    def __init__(self, value, length=1):
        """length is set in 4byte chunks. eg. length = 4 == 16bytes"""
        super(IntegerType, self).__init__(value, length)
        self.byte_length = 4
        self.pattern = "L"


class ShortType(NumericBaseType):
    def __init__(self, value, length=1):
        """length is set in 2byte chunks. eg. length = 4 == 8bytes"""
        super(ShortType, self).__init__(value, length)
        self.byte_length = 2
        self.pattern = "h"


class ByteType(NumericBaseType):
    def __init__(self, value, length=1):
        """length is set in 1byte chunks. eg. length = 4 == 4bytes"""
        super(ByteType, self).__init__(value, length)
        self.byte_length = 1
        self.pattern = "B"


class ContainerType(object):
    """Container type allowing to join several values together"""
    def __init__(self, *args):
        self.values = args

    def __len__(self):
        return sum([len(value) for value in self.values])

    def __str__(self):
        return "".join([str(value) for value in self.values])

    def dump(self):
        """dump binary representation of the contained values"""
        values_binary = "".join([value.dump() for value in self.values])
        return bytes(values_binary)


_types = {
    "string"    : TextType,
    "octets"    : TextType,
    "ipaddr"    : AddressType,
    "ipv6addr"  : AddressType,
    "ipv6prefix": AddressIPv6PrefixType,
    "ether"     : None,
    "date"      : None,
    "integer"   : IntegerType,
    "signed"    : IntegerType,
    "short"     : ShortType,
    "byte"      : ByteType,
    "tlv"       : None,
    }


def bits_to_ip4mask(num_bits):
    """convert integer number of bits in ipv4 netmask to string
    representation of the mask. Eg. '255.255.255.0'"""
    if 0 <= num_bits <= 32:
        bits = 0xffffffff ^ ((1 << (32 - num_bits)) - 1)
        ip4_bytes = [str((bits >> 8*n) & 0xff) for n in range(3, -1, -1)]
        return ".".join(ip4_bytes)
    else:
        raise ValueError("invalid IPv4 mask specified")

def get_type_obj(type_name):
    """Get a type object by name"""
    global _types
    if type_name in _types:
        return _types[type_name]
    raise NotImplementedError("ERROR: the type is not implemented")

def get_type_instance(type_name, *args, **kwargs):
    """Get a type object instance by name"""
    obj = get_type_obj(type_name)
    if not obj:
        raise ValueError("The type is not defined: {}".format(type_name))
    return obj(*args, **kwargs)

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
