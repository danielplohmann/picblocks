init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python3 -m build
publish:
	python3 -m twine upload dist/*
lint:
	ruff check .
	ruff format --check .
	ty check .
test:
	python3 -m pytest tests
test-coverage:
	python3 -m pytest --cov=picblocks --cov-report=html:coverage-html tests
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
