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

all: setup_hooks

build:
	@${PYTHON} setup.py build

install: build
	@echo installing
	@${PYTHON} setup.py install -O2 --record install.log

uninstall:
	@echo uninstalling
	@-test -e install.log && cat install.log | tee | xargs rm || true

setup_hooks:
	@-test -f .git/hooks/post-commit || exit 0
	@-echo 'REVCNT=$$(git rev-list --count master 2>/dev/null)'   >  .git/hooks/post-commit
	@-echo 'REVHASH=$$(git log -1 --format="%h" 2>/dev/null)'     >> .git/hooks/post-commit
	@-echo 'if [[ -z $REVCNT ]]; then VERSION="devel"'            >> .git/hooks/post-commit
	@-echo 'else VERSION="$${REVCNT}.$${REVHASH}"; fi'            >> .git/hooks/post-commit
	@-echo 'echo "__version__ = \"v$${VERSION}\"" > version.py'   >> .git/hooks/post-commit
	@-echo 'echo "Generating a version file... done"'             >> .git/hooks/post-commit
	@-chmod +x .git/hooks/post-commit
	@-cp .git/hooks/post-commit .git/hooks/post-merge
	@-cp .git/hooks/post-commit .git/hooks/post-checkout
	@-/bin/sh .git/hooks/post-checkout

check: test

test: .FORCE doctest
	@echo ":: running unittests:"
	@${PYTHON} -m unittest discover -s ${TESTDIR}

%.dt: .FORCE
	@echo "testing $@"
	@${PYTHON} -m doctest $@

doctest: .FORCE _doctest ${DOCTESTS}
	@echo

_doctest:
	@echo ":: running doctests:"

clean:
	-rm -rf .radi.py.dat
	-rm -rf *.pyc
	-rm -rf libradi/*.pyc
	-rm -rf tests/*.pyc
	-rm -rf MANIFEST
	-rm -rf build dist

clean_hooks:
	-rm -f .git/hooks/post-checkout
	-rm -f .git/hooks/post-commit
	-rm -f .git/hooks/post-merge

.PHONY: build install uninstall test doctest check clean .FORCE

.NOTPARALLEL: setup_hooks
