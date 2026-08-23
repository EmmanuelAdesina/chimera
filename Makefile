.PHONY: install test format lint clean run

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

format:
	black chimera/ tests/
	ruff check --fix chimera/ tests/

lint:
	mypy chimera/
	ruff check chimera/ tests/

run:
	python -m chimera analyze tests/targets/vuln_orders_app.py

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache data/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
