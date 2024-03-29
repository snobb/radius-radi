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


class AttributeDef:

    def __init__(self, attr_name, attr_id, attr_type, attr_vendor=None):
        """ Attribute storage object
        Attribute contains the following:
        - attribute name
        - attribute code (id)
        - attribute type (eg. integer, ipaddr)
        - vendor (if any) (dict of Vendor objects)
        - a list of defined values (if any) (list of name, value tuples)"""
        self.attr_name = attr_name
        self.attr_id = attr_id  # attribute code
        self.attr_type = attr_type
        self.attr_vendor = attr_vendor
        # list of values defined in the dictionary
        self.attr_defined_values = []

    def has_defined_values(self):
        """returns true if the attribute has a list of defined values"""
        return len(self.attr_defined_values) > 0

    def __str__(self):
        content = [
            f"ATTRIBUTE:\tid: {self.attr_id}, "
            f"name: {self.attr_name}, "
            f"type: {self.attr_type}"
        ]
        if self.attr_vendor:
            content.append(f"\t{self.attr_vendor}")

        for name, value in iter(self.attr_defined_values):
            content.append(f"\tVALUE:\tname {name}, value: {value}")
        return "\n".join(content)


class VendorDef:

    def __init__(self, vendor_name, vendor_id):
        """Vendor storage object"""
        self.vendor_name = vendor_name
        self.vendor_id = vendor_id

    def __str__(self):
        return f"VENDOR:\tname: {self.vendor_name}, id: {self.vendor_id}"


class Dictionary:
    """data structure is as follows:
        attributes = { name : Attribute object instance }
        Attribute should know the value id can have and its vendor.
        NOTE: the values are stored as corresponding radtypes values
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
                    self.vendors[record_name.lower()] = VendorDef(
                        record_name, int(vendor_id))
                elif record_type == "BEGIN-VENDOR":
                    vendor = self.vendors[record_name.lower()]
                elif record_type == "END-VENDOR":
                    vendor = None
                else:
                    pass  # ignoring everything we don't know

        return includes

    def read_dictionaries(self, filename, path):
        """read values from dictionary files"""
        full_name = os.path.join(path, filename)
        try:
            for fname in self.read_one_file(full_name):
                self.read_dictionaries(fname, path)
        except IOError:
            raise IOError("Cannot read dictionary (IOError)")

    def read_dictionary(self, filename, path):
        """read dictionary files into a single dictionary db"""
        self.read_dictionaries(filename, path)

        # adding values to the attributes after processing all the files
        for attr_name, values in self.values.items():
            attribute = self.attributes[attr_name]
            if attribute:
                for name, value in values:
                    value_obj = radtypes.get_type_instance(
                        attribute.attr_type, value)
                    attribute.attr_defined_values.append((name, value_obj))

        self.values = None

    def get_attribute(self, name):
        """get attribute by name"""
        try:
            return self.attributes[name.lower()]
        except KeyError:
            raise ValueError(f"attribute {name} not found")

    def get_attribute_names(self):
        """get the list of all known attributes"""
        return self.attributes.keys()

    def __iter__(self):
        return iter(self.attributes)

    def __str__(self):
        contents = []
        for attr in self.attributes.values():
            contents.append(str(attr))
        return "\n".join(contents)


def initialize(dict_path="dict", dict_file="dictionary"):
    global __dict_file, __dict_path
    __dict_path = dict_path
    __dict_file = dict_file


def get_dictionary():
    global __dictionary
    if not __dictionary:
        global __dict_file, __dict_path
        __dictionary = Dictionary(__dict_path, __dict_file)
    return __dictionary


def get_attribute(*args, **kwargs):
    return get_dictionary().get_attribute(*args, **kwargs)


if __name__ == "__main__":
    try:
        get_attribute("test")
    except ValueError:
        pass

    print(__dictionary)
