init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python3 setup.py sdist
publish:
	python3 -m twine upload dist/*
pylint:
	python3 -m pylint --rcfile=.pylintrc picblocks
test:
	python3 -m pytest tests
test-coverage:
	python3 -m pytest --cov=picblocks --cov-report=html:coverage-html tests
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
