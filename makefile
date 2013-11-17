check: test
test:
	python -m unittest discover -s tests/

run:
	python radi.py

clean:
	-rm -rf *.pyc
	-rm -rf tests/*.pyc
