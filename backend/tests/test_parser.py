from codeshield.parsing.parser import parse_file


def test_python_functions_and_containers():
    src = "import os\nclass A:\n    def run(self, q):\n        return q\ndef helper(x):\n    return x\n"
    result = parse_file("a.py", src, "python")
    names = {u.name for u in result.units}
    assert {"run", "helper"} <= names
    run = next(u for u in result.units if u.name == "run")
    assert run.container == "A"
    assert "os" in result.imports


def test_python_syntax_error_is_reported_not_raised():
    result = parse_file("bad.py", "def broken(:\n  pass\n", "python")
    assert result.errors


def test_javascript_functions_found():
    src = "function a(){ return 1; }\nconst b = () => 2;\n"
    result = parse_file("a.js", src, "javascript")
    names = {u.name for u in result.units}
    assert "a" in names


def test_java_method_found():
    src = "public class C {\n  public int f(int x) {\n    return x;\n  }\n}\n"
    result = parse_file("C.java", src, "java")
    assert any(u.name == "f" for u in result.units)


def test_chunking_respects_token_budget():
    from codeshield.parsing.parser import chunk_source

    big = "\n".join(f"x{i} = {i}" for i in range(2000))
    chunks = list(chunk_source(big, max_tokens=200))
    assert len(chunks) > 1
