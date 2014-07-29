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
        super(TextType, self).__init__(str(value))

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



class IntegerType(AbstractType):
    """Integer data type"""
    def __init__(self, value, length=1):
        """length is set in 4byte chunks. eg. length = 4 == 16bytes"""
        super(IntegerType, self).__init__(int(value))
        self.length = length


    def __len__(self):
        return self.length * 4


    def __str__(self):
        return str(self.value)


    def dump(self):
        values = [self.value >> (n*32) & 0xffffffff
                for n in range(self.length-1, -1, -1)]
        return struct.pack("!%dL" % len(values), *values)



class ByteType(AbstractType):
    """Byte data type"""
    def __init__(self, value):
        super(ByteType, self).__init__(int(value))
        if value < 0 or value > 0xff:
            raise ValueError("byte - type overflow")


    def __len__(self):
        return 1


    def __str__(self):
        return str(self.value)


    def dump(self):
        """dump binary value"""
        return struct.pack("!B", self.value)



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
    "ipv6prefix": AddressType,
    "ether"     : None,
    "date"      : None,
    "integer"   : IntegerType,
    "signed"    : IntegerType,
    "short"     : None,
    "byte"      : ByteType,
    "tlv"       : None,
    }



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
        raise ValueError("The type is not defined")
    return obj(*args, **kwargs)




# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
