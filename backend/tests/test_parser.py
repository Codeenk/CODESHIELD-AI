from codeshield.parsing.parser import chunk_source, detect_language, parse_file


def test_python_functions_and_containers():
    src = "import os\nclass A:\n    def run(self, q):\n        return q\ndef helper(x):\n    return x\n"
    result = parse_file("a.py", src)
    names = {u.name for u in result.units}
    assert {"A.run", "helper"} <= names
    run = next(u for u in result.units if u.name == "A.run")
    assert run.container == "A"
    module = next(u for u in result.units if u.name == "<module>")
    assert "import os" in module.source


def test_python_syntax_error_is_reported_not_raised():
    result = parse_file("bad.py", "def broken(:\n  pass\n")
    assert result.error


def test_javascript_functions_found():
    src = "function a(){ return 1; }\nconst b = () => 2;\n"
    result = parse_file("a.js", src)
    assert {"a", "b"} <= {u.name for u in result.units}


def test_java_method_found():
    src = "public class C {\n  public int f(int x) {\n    return x;\n  }\n}\n"
    result = parse_file("C.java", src)
    assert any(u.name == "C.f" for u in result.units)


def test_unknown_language_is_reported():
    result = parse_file("notes.txt", "hello")
    assert result.error and not result.units
    assert detect_language("NOTES.TXT") == "unknown"


def test_chunking_respects_line_budget():
    big = "\n".join(f"x{i} = {i}" for i in range(2000))
    chunks = chunk_source(big, max_lines=200, overlap=20)
    assert len(chunks) > 1
    assert max(len(chunk.splitlines()) for chunk in chunks) <= 200
