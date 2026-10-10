"""Deliberately safe sample — should produce no findings."""
import hashlib
import json
import os
import subprocess

DEBUG = False


def get_user(cursor, user_id):
    # Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def ping(host):
    # No shell, argument list
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def restore(blob):
    # Safe format
    return json.loads(blob)


def hash_password(raw):
    # Strong hashing
    return hashlib.sha256(raw.encode()).hexdigest()


def read_report(secure_filename, base="/var/reports"):
    # Confined path
    path = os.path.abspath(os.path.join(base, secure_filename))
    if not path.startswith(os.path.abspath(base)):
        raise ValueError("path traversal")
    with open(path) as handle:
        return handle.read()
