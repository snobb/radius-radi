#!/usr/bin/env python
#
# read_dict.py
# Author: Alex Kozadaev (2014)
#

import os.path

types = [
    "string",
    "ipaddr",
    "octets",
    "date",
    "integer",
    "ipv6addr"
    ]

class Dictionary(object):
    """
    datastructure is as follows:
    vendor = {
        "generic": { # non-vendor specific AVPs
            "id": -1,
            "attributes": {
                <NAME>  : (value  : type <see types variable>)
                <NAME1> : (value1 : type1)
            }
            "values": {
                <NAME>  : [
                    (value  : type <see types variable>),
                    (value1 : type1)
                ]
                <NAME1> : [ ... ]
            }
        }
        "3gpp": {
            ... see "generic above
        }
    }
    """
    def __init__(self):
        """RADIUS dictionary repository"""
        self.types = {}
        self.vendor = {"generic": {
            "id": -1,
            "attributes":{},
            "values":{}
            }}
        self.generic_repo = "generic"

    def create_vendor(self, vendor_name, vendor_id):
        """create a vendor (if it does not exists)"""
        self.vendor.setdefault(vendor_name, {
            "id": vendor_id,
            "attributes": {},
            "values": {}
            })

    def switch_vendor(self, vendor=None):
        """create vendor - if None, use generic
        vendor: vendor name
        return: tuple of attributes and values dictionaries
        """
        if not vendor:
            vendor = self.generic_repo
        attributes = self.vendor[vendor]["attributes"]
        values = self.vendor[vendor]["values"]
        return (attributes, values)

    def read_one_file(self, filename):
        """read a single dictionary file"""
        includes = []
        attributes, values = self.switch_vendor(None)
        with open(filename) as f:
            for line in f:
                field = line.split()
                if len(field) == 0 or field[0][0] == '#':
                    continue

                attr_type, attr_name = field[:2]
                if attr_type == "$INCLUDE":
                    includes.append(attr_name)
                elif attr_type == "ATTRIBUTE":
                    attributes[attr_name.lower()] = tuple(field[2:4])
                    self.types.setdefault(field[3], 0)
                elif attr_type == "VALUE":
                    values.setdefault(attr_name.lower(),
                            []).append(tuple(field[2:4]))
                elif attr_type == "VENDOR":
                    self.create_vendor(attr_name.lower(), field[2])
                elif attr_type == "BEGIN-VENDOR":
                    attributes, values = self.switch_vendor(attr_name.lower())
                elif attr_type == "END-VENDOR":
                    attributes, values = self.switch_vendor(None)
                else:
                    pass

        return includes

    def read_dictionary(self, filename, path):
        """read values from dictionary files"""
        full_name = os.path.join(path, filename)
        for fname in self.read_one_file(full_name):
            self.read_dictionary(fname, path)

if __name__ == "__main__":
    dict_path = "dict"
    d = Dictionary()
    d.read_dictionary("dictionary", dict_path)

    print "Attributes:"
    print d.vendor["3gpp"]["attributes"]
    print d.types

# vim: ts=4 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
