# A make file for python projects with doctest/unittest facilities
#
# The directory layout should be as follows:
# /
# |\_ tests		-	unittests
# |\_ doctests  -	doctests (file extension should be .dt)
# |\_ ... 		-	project code
# \__ makefile	-	this makefile
#
# The make file is also assumes the use of setup.py
#
PYTHON = python
TESTDIR = tests
DOCTESTS = ${wildcard doctests/*.dt}

build:
	@${PYTHON} setup.py build

install: build
	@echo installing
	@${PYTHON} setup.py install -O2 --record install.log

uninstall:
	@echo uninstalling
	@-test -e install.log && cat install.log | tee | xargs rm || true

check: test

test: ${DOCTESTS}
	@echo "\nrunning unittests:"
	@${PYTHON} -m unittest discover -s ${TESTDIR}

%.dt: .FORCE
	@echo "testing $@"
	@${PYTHON} -m doctest $@

clean:
	-rm -rf .radi.py.dat
	-rm -rf *.pyc
	-rm -rf libradi/*.pyc
	-rm -rf tests/*.pyc
	-rm -rf MANIFEST
	-rm -rf build dist

.PHONY: build install uninstall test check clean .FORCE
