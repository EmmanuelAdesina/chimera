.PHONY: install test format lint clean run

install:
\tpip install -e \".[dev]\"

test:
\tpytest tests/ -v --tb=short

format:
\tblack chimera/ tests/
\truff check --fix chimera/ tests/

lint:
\tmypy chimera/
\truff check chimera/ tests/

run:
\tpython -m chimera analyze

clean:
\trm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache data/
\tfind . -type d -name __pycache__ -exec rm -rf {} +
\tfind . -type f -name '*.pyc' -delete
