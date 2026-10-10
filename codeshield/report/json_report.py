"""JSON report writer."""

from __future__ import annotations

import json
from typing import Any

from ..models import ScanResult


def to_dict(scan: ScanResult) -> dict[str, Any]:
    return json.loads(scan.model_dump_json())


def to_json(scan: ScanResult, indent: int = 2) -> str:
    return scan.model_dump_json(indent=indent)
