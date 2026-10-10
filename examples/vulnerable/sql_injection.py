"""Example: SQL injection (CWE-89). Intentionally vulnerable — do not deploy."""

import sqlite3


def get_user(username: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: the username is interpolated straight into the statement.
    cursor.execute(f"SELECT id, name FROM users WHERE name = '{username}'")
    return cursor.fetchall()


def search(table: str, term: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: concatenation with request-ish input.
    cursor.execute("SELECT * FROM " + table + " WHERE name = '" + term + "'")
    return cursor.fetchall()
