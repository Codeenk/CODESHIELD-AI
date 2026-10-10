"""Example: OS command injection (CWE-78). Intentionally vulnerable — do not deploy."""

import os
import subprocess


def ping_host(host: str) -> int:
    # Vulnerable: host is passed to the shell.
    return os.system("ping -c 1 " + host)


def convert(path: str) -> str:
    # Vulnerable: shell=True re-enables shell interpretation.
    result = subprocess.run("convert " + path + " out.png", shell=True, capture_output=True)
    return result.stdout.decode(errors="replace")
