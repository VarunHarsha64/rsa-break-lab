"""
logging_utils.py
-----------------
Every attack run emits two things:

1. A human-readable line on the console (so a live demo looks alive).
2. A structured JSON line appended to a .jsonl log file (so the
   benchmarking script and the report generator can later crunch the
   numbers without re-parsing free text).

This keeps "the demo" and "the statistics behind the demo" generated
by the exact same code path, so the numbers in your report are always
reproducible from the logs in this repo.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_LOG_PATH = Path("logs/attack_log.jsonl")


@dataclass
class AttackResult:
    attack: str
    success: bool
    duration_ms: float
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class AttackLogger:
    """Records attack attempts to console + a JSONL file.

    Usage:
        logger = AttackLogger()
        with logger.timed("fermat", n_bits=512) as ctx:
            result = fermat_factor(n)
            ctx.success = result is not None
            ctx.details["iterations"] = iterations
    """

    def __init__(self, log_path: Path | str = DEFAULT_LOG_PATH, echo: bool = True):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.echo = echo

    def _write(self, result: AttackResult) -> None:
        with self.log_path.open("a") as f:
            f.write(result.to_json() + "\n")
        if self.echo:
            status = "SUCCESS" if result.success else "FAILED "
            extras = ", ".join(f"{k}={v}" for k, v in result.details.items())
            print(
                f"[{result.timestamp}] {status}  {result.attack:<16} "
                f"{result.duration_ms:8.2f} ms  {extras}"
            )

    @contextmanager
    def timed(self, attack: str, **initial_details: Any):
        ctx = _TimedContext(attack, initial_details)
        start = time.perf_counter()
        try:
            yield ctx
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0
            result = AttackResult(
                attack=attack,
                success=ctx.success,
                duration_ms=duration_ms,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
                details=ctx.details,
            )
            self._write(result)
            ctx.result = result


class _TimedContext:
    def __init__(self, attack: str, initial_details: Dict[str, Any]):
        self.attack = attack
        self.success: bool = False
        self.details: Dict[str, Any] = dict(initial_details)
        self.result: Optional[AttackResult] = None


def read_log(log_path: Path | str = DEFAULT_LOG_PATH):
    """Yield AttackResult-like dicts from a JSONL log file."""
    path = Path(log_path)
    if not path.exists():
        return
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)
