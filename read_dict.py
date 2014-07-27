#!/usr/bin/env python
#
# read_dict.py
# Author: Alex Kozadaev (2014)
#

import os.path
import struct

class AttributeDef(object):
    def __init__(self, attr_name, attr_id, attr_type,
            attr_vendor=None, attr_value=None):
        """Attribute storage object
        Attribute contains the following:
        - attribute name
        - attribute code (id)
        - attribute type (eg. integer, ipaddr)
        - vendor (if any) (dict of Vendor objects)
        - a list of defined values (if any) (list of name, value tuples)"""
        self.attr_name = attr_name
        self.attr_id = attr_id # attribute code
        self.attr_type = attr_type
        self.attr_vendor = attr_vendor
        # dictionary of values defined in the dictionary
        self.attr_defined_values = []

    def __str__(self):
        content = [("ATTRIBUTE: id: {}, name: {}, type: {}"
                        .format(self.attr_id, self.attr_name, self.attr_type))]
        if self.attr_vendor:
            content.append("\t{}".format(self.attr_vendor))

        for name, value in iter(self.attr_defined_values):
            content.append("\tVALUE: name {}, value: {}".format(
                name, value))
        return "\n".join(content)


class VendorDef(object):
    def __init__(self, vendor_name, vendor_id):
        """Vendor storage object"""
        self.vendor_name = vendor_name
        self.vendor_id = vendor_id

    def __str__(self):
        return ("VENDOR: name: {}, id: {}"
                    .format(self.vendor_name, self.vendor_id))


class Dictionary(object):
    """data structure is as follows:
        attributes = { name : Attribute object instance }
    Attribute should now the value id can have and its vendor.
    """
    def __init__(self):
        self.attributes = {}
        self.vendors = {}
        self.values = {}


    def read_one_file(self, filename):
        """read a single dictionary file"""
        includes = []
        vendor = None
        with open(filename) as f:
            for line in f:
                field = line.split()
                if len(field) == 0 or field[0][0] == '#':
                    continue

                record_type, record_name = field[:2]
                if record_type == "$INCLUDE":
                    includes.append(record_name)
                elif record_type == "ATTRIBUTE":
                    attr_id, attr_type = field[2:4]
                    attribute = AttributeDef(record_name, attr_id,
                            attr_type, vendor)
                    self.attributes[record_name.lower()] = attribute
                elif record_type == "VALUE":
                    val_name, val_value = field[2:4]
                    self.values.setdefault(record_name.lower(), []).append(
                        (val_name, val_value))
                elif record_type == "VENDOR":
                    vendor_id = field[2]
                    self.vendors[record_name.lower()] = VendorDef(record_name,
                            vendor_id)
                elif record_type == "BEGIN-VENDOR":
                    vendor = self.vendors[record_name.lower()]
                elif record_type == "END-VENDOR":
                    vendor = None
                else:
                    pass

        return includes


    def read_dictionaries(self, filename, path):
        """read values from dictionary files"""
        full_name = os.path.join(path, filename)
        for fname in self.read_one_file(full_name):
            self.read_dictionaries(fname, path)


    def read_dictionary(self, filename, path):
        self.read_dictionaries(filename, path)

        # adding values to the attributes after processing all the files
        for attr_name, values in self.values.iteritems():
            attribute = self.attributes[attr_name]
            if attribute:
                for name, value in values:
                    attribute.attr_defined_values.append((name, value))

        self.values = None


    def __str__(self):
        contents = []
        for attr in self.attributes.itervalues():
            contents.append(str(attr))
        return "\n".join(contents)


if __name__ == "__main__":
    dict_path = "dict"
    rad_dict = Dictionary()
    rad_dict.read_dictionary("dictionary", dict_path)

    print rad_dict

# vim: ts=3 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
