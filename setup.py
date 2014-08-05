#!/usr/bin/env python
#
# { setup.py }
# Copyright (C) 2013 Alex Kozadaev [akozadaev at yahoo com]
#

from distutils.core import setup


setup(
        name="libradi",
        description=(
            "libradi - radius accounting library"),
        author="Alex Kozadaev",
        author_email="a.kozadaev at f5 com",
        license=("Alex Kozadaev <a.kozadaev at f5.com>\n\n"
            "Copyright (c) 2013-2014, F5 Networks, Inc. All rights reserved.\n\n"
            "No part of this software may be reproduced or transmitted in any\n"
            "form or by any means, electronic or mechanical, for any purpose,\n"
            "without express written permission of F5 Networks, Inc.\n"
            ),
        version="0.05",
        scripts=["radi.py"],
        py_modules=["libradi.dictionary", "libradi.radius", "libradi.radtypes"],
        )


# vim: set ts=4 sts=4 sw=4 tw=80 ai smarttab et list
