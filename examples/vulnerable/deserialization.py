"""Example: insecure deserialization (CWE-502) + weak hash (CWE-328). Intentionally vulnerable."""

import hashlib
import pickle

import yaml


def load_session(blob: bytes):
    # Vulnerable: unpickling untrusted bytes executes arbitrary code.
    return pickle.loads(blob)


def load_config(text: str):
    # Vulnerable: default loader can construct arbitrary objects.
    return yaml.load(text)


def fingerprint(data: bytes) -> str:
    # Vulnerable: MD5 is collision-broken.
    return hashlib.md5(data).hexdigest()
