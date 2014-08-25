check: test

test:
	@echo testing project
	@python -c "import tests"

run:
	python radi.py

build:
	python setup.py build

install: build
	@echo installing
	python setup.py install -O2 --record install.log

uninstall:
	@echo uninstalling
	-test -e install.log && cat install.log | xargs rm || true

clean:
	-rm -rf .radi.py.dat
	-rm -rf *.pyc
	-rm -rf libradi/*.pyc
	-rm -rf tests/*.pyc
	-rm -rf MANIFEST
	-rm -rf build dist
