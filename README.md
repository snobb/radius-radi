libradi/radi - A radius tool to start/stop subscriber session
=============================================================

DESIGN PROBLEMS TO SOLVE:
-------------------------

   * storage of values in the AVP data structures (currently it's the radtypes classes).
   * the value storage currently is a list of tuples. [ (name, value), (name1, value1) ].
      * Given the size of the list isn't big, the linear search may be acceptable here. Should I consider changing it to dictionary?
      (Currently converting to dict every time we need to check)


DESIGN OF THE DICTIONARY STRUCTURE:
-----------------------------------
```
    Dictionary = {
        ATTRIBUTE_NAME : AttributeDef Obj,
        ...
    }

    class AttributeDef {
        attr_name           # name of the attribute (key)
        attr_id             # numeric ID of the attribute
        attr_type           # string representation of type
        attr_vendor         # VendorDef object reference (1->1)
        attr_defined_values # list of tuples (name_str, value_str)
    }

    class VendorDef {
        vendor_name         # name of the vendor
        vendor_id           # numeric ID
    }

    class Dictionary {
        attributes          # dict { attr_name : AttributeDef obj, ... }
        vendors             # dict { vendor_name : VendorDef obj, ... }
        values              # dict { attr_name : (name, value) }

        # values dictionary is used to add the values to attributes
        # after all files are processed since the values for
        # an attribute can be spread across multiple files.

        methods {
            get_attribute       # get the attribute by name

            read_dictionaries   # read all dictionary files following
                                # the $INCLUDE clause

            read_dictionary     # start reading dictionaries and process
                                # values once all files are processed

            read_one_file       # parse a single file and fill the data
                                # structure. Returns a list of included
                                # files
        }
    }
```

Each type MUST implement dump method that is used to get the binary representation of the Attribute/Value value.


DESIGN OF THE AVP OBJECT:
-------------------------

```
    class RadiusAvp {
        avp_def             # AttributeDef (definition of the attribute)
        avp_code            # number id value (IntegerType obj)
        avp_value           # value of the avp (radtypes[avp_def.avp_type] obj
        avp_subavp          # list of sub AVPs (in case of the vendor specific).

        methods {
            dump            # dump binary representation of the AVP
        }
    }
```

Each type MUST implement dump method that is used to get the binary representation of the AVP value.


DESIGN OF RADTYPES OBJECT:
--------------------------

Most of the Radius types are derived from the AbstractType class.
AbstractType implements the comparator methods and *\_\_str\_\_* and more importantly leaves the method dump unimplemented so that each type class implement it accordingly.

```
    class AbstractType {
        fields {
            value   # stored value
            length  # length of value in units (eg. Integer: unit = 4bytes)
        }
        implements {
            __len__
            __lt__
            __le__
            __eq__
            __ne__
            __gt__
            __ge__
            __str__
        }

        abstract methods {
            dump()  # dump the type value as a binary string
        }
    }
```

Numeric class have the base NumericBaseType class which implements common functionality.

Each type MUST implement dump method that is used to get the binary representation of the Type value


DESIGN OF LIBRADI LIBRARY:
--------------------------

```
    libradi.radtypes.*      # type objects for storing values as per
                            # dictionary attribute type

    libradi.dictionary.*    # functions related to dictionary

    libradi.*               # radius related objects/functions
```

