from chimera.parsers.languages.python_parser import PythonParser

def test_name():
    assert PythonParser().name == "python_ast"
