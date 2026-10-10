"""Smoke evaluation of the CodeBERT detector against the rule baseline (PRD §8.1, §11.4).

This is a **small, hand-labelled smoke set**, NOT the project-disjoint benchmark the PRD calls
for. It exists to (a) prove the model path runs end-to-end and (b) give an honest first read on
precision/recall, including the model's false positives.

    python scripts/eval_model.py [--threshold 0.55] [--no-model]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeshield.config import Settings  # noqa: E402
from codeshield.core import rules  # noqa: E402
from codeshield.core.detection import CodeBERTDetector  # noqa: E402


@dataclass
class Sample:
    name: str
    path: str
    code: str
    label: int  # 1 = vulnerable, 0 = secure


VULNERABLE = [
    Sample("sql-fstring", "a.py", 'def f(u):\n    return cur.execute(f"SELECT * FROM t WHERE n=\'{u}\'")\n', 1),
    Sample("os.system", "a.py", 'import os\ndef f(h):\n    return os.system("ping " + h)\n', 1),
    Sample("subprocess-shell", "a.py", 'import subprocess\ndef f(p):\n    return subprocess.run("cat " + p, shell=True)\n', 1),
    Sample("pickle", "a.py", 'import pickle\ndef f(b):\n    return pickle.loads(b)\n', 1),
    Sample("yaml-load", "a.py", 'import yaml\ndef f(t):\n    return yaml.load(t)\n', 1),
    Sample("eval", "a.py", 'def f(x):\n    return eval(x)\n', 1),
    Sample("innerHTML", "a.js", 'function f(u){ document.getElementById("o").innerHTML = u; }\n', 1),
    Sample("runtime-exec", "A.java", 'class A { String f(String h) throws Exception { Runtime.getRuntime().exec("ping " + h); return h; } }\n', 1),
    Sample("md5", "a.py", 'import hashlib\ndef f(b):\n    return hashlib.md5(b).hexdigest()\n', 1),
    Sample("hardcoded", "a.py", 'API_KEY = "sk-live-9f2c7a41deadbeef001122334455"\n', 1),
]

SECURE = [
    Sample("add", "a.py", "def add(a, b):\n    return a + b\n", 0),
    Sample("parameterised-sql", "a.py", 'def f(cur, u):\n    return cur.execute("SELECT * FROM t WHERE n=?", (u,))\n', 0),
    Sample("subprocess-list", "a.py", 'import subprocess\ndef f(p):\n    return subprocess.run(["cat", p], shell=False, check=True)\n', 0),
    Sample("json-loads", "a.py", "import json\ndef f(b):\n    return json.loads(b)\n", 0),
    Sample("textcontent", "a.js", 'function f(u){ document.getElementById("o").textContent = u; }\n', 0),
    Sample("sha256", "a.py", "import hashlib\ndef f(b):\n    return hashlib.sha256(b).hexdigest()\n", 0),
    Sample("env-secret", "a.py", 'import os\nAPI_KEY = os.environ["API_KEY"]\n', 0),
    Sample("allowlist-path", "a.py", 'import os\nBASE = "/srv/data"\ndef f(name):\n    p = os.path.realpath(os.path.join(BASE, name))\n    return open(p) if p.startswith(BASE) else None\n', 0),
    Sample("allowlist-url", "a.py", 'ALLOWED = {"https://api.example.com"}\ndef f(url):\n    return url in ALLOWED\n', 0),
    Sample("csprng", "a.py", "import secrets\ndef token():\n    return secrets.token_urlsafe(32)\n", 0),
]


def confusion(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / max(1, len(y_true))
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "accuracy": round(accuracy, 3), "mcc": round(mcc, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=0.55)
    parser.add_argument("--no-model", action="store_true")
    args = parser.parse_args()

    settings = Settings(disable_model=args.no_model, model_threshold=args.threshold)
    detector = CodeBERTDetector(settings)
    model_ok = detector.available()
    print(f"CodeBERT detector: available={model_ok} note={detector.load_error}")
    print(f"threshold={settings.model_threshold}\n")

    samples = VULNERABLE + SECURE
    y_true, model_pred, rule_pred = [], [], []
    rows = []

    for sample in samples:
        rule_hits = rules.scan_text(sample.path, sample.code)
        r = 1 if rule_hits else 0
        if model_ok:
            prediction = detector.predict(sample.code)
            prob = prediction.probability if prediction else 0.0
            m = 1 if (prediction and prediction.probability >= settings.model_threshold) else 0
        else:
            prob, m = float("nan"), 0
        y_true.append(sample.label)
        model_pred.append(m)
        rule_pred.append(r)
        rows.append((sample.name, sample.label, prob, m, r, [f.cwe for f in rule_hits]))

    print(f"{'sample':<20} {'truth':>5} {'prob':>7} {'model':>5} {'rules':>5}  rule CWE")
    print("-" * 70)
    for name, label, prob, m, r, cwes in rows:
        prob_s = "n/a" if prob != prob else f"{prob:.3f}"
        mark = lambda v: "VULN" if v else "ok"  # noqa: E731
        print(f"{name:<20} {'VULN' if label else 'ok':>5} {prob_s:>7} {mark(m):>5} {mark(r):>5}  {','.join(cwes)}")

    print(f"\nmodel  {json.dumps(confusion(y_true, model_pred))}")
    print(f"rules  {json.dumps(confusion(y_true, rule_pred))}")
    print(
        "\nNOTE: 20 hand-labelled samples only — a smoke check, not the PRD §8.1 benchmark.\n"
        "The model card reports 65.3% accuracy on its own (random, not project-disjoint) split."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
