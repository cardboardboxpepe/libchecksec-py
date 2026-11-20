"""Require diagnostics for each deliberately invalid consumer operation."""

import json
import subprocess
from typing import TypedDict, cast


class Position(TypedDict):
    """Source position reported by BasedPyright."""

    line: int


class Range(TypedDict):
    """Diagnostic source range."""

    start: Position


class Diagnostic(TypedDict):
    """Fields used to verify each expected diagnostic."""

    range: Range
    severity: str
    rule: str


class Output(TypedDict):
    """BasedPyright JSON output fields used by this check."""

    generalDiagnostics: list[Diagnostic]


completed = subprocess.run(
    ["basedpyright", "--outputjson", "--project", "pyrightconfig.json", "invalid.py"],
    capture_output=True,
    text=True,
    check=False,
)
if completed.returncode != 1:
    raise SystemExit(f"Expected type errors, got exit {completed.returncode}: {completed.stderr}")
output = cast(Output, json.loads(completed.stdout))
diagnostics = output["generalDiagnostics"]
errors = {(item["range"]["start"]["line"] + 1, item.get("rule")) for item in diagnostics if item["severity"] == "error"}
if errors != {(5, "reportArgumentType"), (6, "reportGeneralTypeIssues")}:
    raise SystemExit(f"Missing expected consumer errors: {diagnostics}")
