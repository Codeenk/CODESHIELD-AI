"""Example: hard-coded credentials (CWE-798). Intentionally vulnerable — do not deploy."""

API_KEY = "sk-live-9f2c7a41deadbeef001122334455"
DB_PASSWORD = "SuperSecret123!"


def call_api():
    import requests

    return requests.get("https://api.example.com/data", headers={"Authorization": API_KEY})
