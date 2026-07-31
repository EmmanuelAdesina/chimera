# Chimera Plugins

## How to Extend

Drop a Python module here or install as a separate package with entry points.

## Plugin Types

- Parser: chimera.parsers.base.BaseParser
- Analyzer: chimera.analysis.base.BaseAnalyzer
- Bridge: chimera.execution.base.ExecutionAdapter
- Reporter: chimera.reports.base.BaseReporter

## Rules
1. Lazy-load heavy dependencies
2. Return Pydantic models
3. Handle your own exceptions
