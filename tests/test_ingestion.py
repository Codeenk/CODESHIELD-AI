import io
import zipfile

from codeshield.config import Settings
from codeshield.core.ingestion import ingest_directory, ingest_upload, should_skip_path


def test_skip_vendored_and_generated():
    assert should_skip_path("node_modules/pkg/index.js")
    assert should_skip_path("dist/bundle.min.js")
    assert should_skip_path("src/app.min.js")
    assert should_skip_path("a/b/__pycache__/x.py")
    assert should_skip_path("src/app.py") is None


def test_size_limits_reject_large_files():
    settings = Settings(max_file_bytes=10)
    [file] = ingest_upload("big.py", b"x = 1\n" * 100, settings)
    assert file.skipped
    assert "size" in (file.skip_reason or "")


def test_binary_files_are_skipped():
    [file] = ingest_upload("blob.py", b"\x00\x01\x02binary", Settings())
    assert file.skipped
    assert file.skip_reason == "binary file"


def test_unsupported_extension_skipped():
    [file] = ingest_upload("notes.txt", b"hello", Settings())
    assert file.skipped
    assert file.skip_reason == "unsupported file type"


def test_zip_ingestion_filters_content():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hi')\n")
        archive.writestr("node_modules/dep/index.js", "console.log(1)\n")
        archive.writestr("image.png", "not really an image")

    by_path = {f.path: f for f in ingest_upload("bundle.zip", buffer.getvalue(), Settings())}
    assert not by_path["app.py"].skipped
    assert by_path["app.py"].language == "python"
    assert by_path["node_modules/dep/index.js"].skipped
    assert "image.png" not in by_path  # unsupported type, never ingested


def test_invalid_zip_is_reported():
    [file] = ingest_upload("broken.zip", b"not a zip", Settings())
    assert file.skipped
    assert file.skip_reason == "invalid zip archive"


def test_directory_ingestion_finds_python(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    (tmp_path / "b.txt").write_text("ignore me\n")
    files = ingest_directory(str(tmp_path))
    by_path = {f.path: f for f in files}
    assert "a.py" in by_path
    assert not by_path["a.py"].skipped
    assert by_path["b.txt"].skipped
