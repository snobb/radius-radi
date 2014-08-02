#!/usr/bin/env python
#
# read_dict.py
# Author: Alex Kozadaev (2014)
#

import os.path
import radtypes

__dictionary = None
__dict_path = "dict"
__dict_file = "dictionary"


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
        # list of values defined in the dictionary
        self.attr_defined_values = []


    def __str__(self):
        content = [("ATTRIBUTE:\tid: {}, name: {}, type: {}"
                        .format(self.attr_id, self.attr_name, self.attr_type))]
        if self.attr_vendor:
            content.append("\t{}".format(self.attr_vendor))

        for name, value in iter(self.attr_defined_values):
            content.append("\tVALUE:\tname {}, value: {}".format(
                name, value))
        return "\n".join(content)



class VendorDef(object):
    def __init__(self, vendor_name, vendor_id):
        """Vendor storage object"""
        self.vendor_name = vendor_name
        self.vendor_id = vendor_id


    def __str__(self):
        return ("VENDOR:\tname: {}, id: {}"
                    .format(self.vendor_name, self.vendor_id))



class Dictionary(object):
    """data structure is as follows:
        attributes = { name : Attribute object instance }
    Attribute should now the value id can have and its vendor.
    NOTE: the values are stored as string regardless of type.
          Eg. integer 100 will still be stored as "100" hence
          casting IS REQUIRED upon using the values.
          This feature is subject to change in future.
    """
    def __init__(self, dict_path="dict", dict_file="dictionary"):
        self.dict_path = dict_path
        self.dict_file = dict_file
        self.attributes = {}
        self.vendors = {}
        self.values = {}
        self.read_dictionary(self.dict_file, self.dict_path)


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
                    attribute = AttributeDef(record_name, int(attr_id),
                            attr_type, vendor)
                    self.attributes[record_name.lower()] = attribute
                elif record_type == "VALUE":
                    val_name, val_value = field[2:4]
                    self.values.setdefault(record_name.lower(), []).append(
                        (val_name, val_value))
                elif record_type == "VENDOR":
                    vendor_id = field[2]
                    self.vendors[record_name.lower()] = VendorDef(record_name,
                            int(vendor_id))
                elif record_type == "BEGIN-VENDOR":
                    vendor = self.vendors[record_name.lower()]
                elif record_type == "END-VENDOR":
                    vendor = None
                else:
                    pass # ignoring everything we don't know

        return includes


    def read_dictionaries(self, filename, path):
        """read values from dictionary files"""
        full_name = os.path.join(path, filename)
        for fname in self.read_one_file(full_name):
            try:
                self.read_dictionaries(fname, path)
            except IOError:
                print "Error: cannot find a file"


    def read_dictionary(self, filename, path):
        self.read_dictionaries(filename, path)

        # adding values to the attributes after processing all the files
        for attr_name, values in self.values.iteritems():
            attribute = self.attributes[attr_name]
            if attribute:
                for name, value in values:
                    value_obj = radtypes.get_type_instance(
                            attribute.attr_type, value)
                    attribute.attr_defined_values.append(
                            (name, value_obj))

        self.values = None


    def get_attribute(self, name):
        try:
            return self.attributes[name.lower()]
        except KeyError:
            raise ValueError("attribute not found")


    def __str__(self):
        contents = []
        for attr in self.attributes.itervalues():
            contents.append(str(attr))
        return "\n".join(contents)


def get_dictionary():
    return __dictionary

def get_attribute(*args, **kwargs):
    global __dictionary, __dict_path, __dict_file
    if not __dictionary:
        __dictionary = Dictionary(__dict_path, __dict_file)
    return __dictionary.get_attribute(*args, **kwargs)


if __name__ == "__main__":
    try:
        get_attribute("test")
    except ValueError:
        pass

    print __dictionary

# vim: ts=3 sts=4 sw=4 tw=80 ai smarttab et fo=rtcq list
