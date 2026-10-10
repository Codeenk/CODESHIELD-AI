"""Deliberately vulnerable sample — used by the demo and tests."""
import hashlib
import os
import pickle

DEBUG = True
API_KEY = "sk_live_1234567890abcdef"

DB = None  # a pretend cursor


def get_user(user_id):
    # SQL injection via string concatenation
    DB.execute("SELECT * FROM users WHERE id = " + user_id)
    return DB.fetchone()


def ping(host):
    # OS command injection
    os.system("ping -c 1 " + host)


def restore(blob):
    # Insecure deserialization
    return pickle.loads(blob)


def hash_password(raw):
    # Weak hashing
    return hashlib.md5(raw.encode()).hexdigest()


def read_report(name):
    # Path traversal
    with open("/var/reports/" + name) as handle:
        return handle.read()
