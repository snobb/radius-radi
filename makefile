check: test
test:
	python -m unittest discover -s tests/

run:
	python radi.py

build:
	python setup.py build

install: build
	python setup.py install --record install.log

clean:
	-rm -rf *.pyc
	-rm -rf libradi/*.pyc
	-rm -rf tests/*.pyc
	-rm -rf build
