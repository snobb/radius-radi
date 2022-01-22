#!/usr/bin/env python
#
# { setup.py }
# Copyright (C) 2013 Alex Kozadaev [akozadaev at yahoo com]
#

import os
import glob
import distutils.sysconfig
from distutils.core import setup

import libradi


def create_config_file():
    with open("libradi/config.py", "w") as f:
        print(f"install_pfx = '{distutils.sysconfig.PREFIX}'", file=f)


def delete_config_file():
    os.remove("libradi/config.py")


def main():
    create_config_file()
    setup(name=libradi.__name__,
          description=libradi.__doc__,
          author=libradi.__author__,
          author_email=libradi.__author_email__,
          license=libradi.__license__,
          version=libradi.__version__,
          scripts=["radi.py"],
          py_modules=[
              "libradi.dictionary", "libradi.radius", "libradi.radtypes",
              "libradi.config"
          ],
          data_files=[("share/libradi/dict", glob.glob("dict/dictionary*"))])
    delete_config_file()


if __name__ == "__main__":
    try:
        main()
    except IOError as e:
        print("ERROR: cannot access config.py")
        exit(1)
