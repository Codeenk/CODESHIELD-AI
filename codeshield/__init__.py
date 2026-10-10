"""CodeShield AI — AI-powered source code vulnerability scanner & explainable auto-repair engine.

The package implements the six-stage pipeline described in ``PRD.md``:

    ingest -> parse -> detect -> explain -> repair -> verify

The rule-based baseline works with no heavy dependencies; the CodeBERT detector and the
LLM repair model are optional and loaded lazily.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
