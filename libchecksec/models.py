"""Immutable, transport-independent analysis results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Represent the outcome of a security check."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    FULL = "full"
    PARTIAL = "partial"
    ABSENT = "absent"
    PRESENT = "present"
    DSO = "dso"


@dataclass(frozen=True)
class Finding:
    """Describe a check by status, supporting evidence and optional reason."""

    status: Status
    evidence: tuple[str, ...] = ()
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible representation of this finding."""
        result: dict[str, Any] = {"status": self.status.value, "evidence": list(self.evidence)}
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True)
class FortifyFinding:
    """Describe fortification status, symbol coverage, evidence and reason."""

    status: Status
    fortified_symbols: tuple[str, ...] = ()
    fortifiable_symbols: tuple[str, ...] | None = None
    coverage: float | None = None
    evidence: tuple[str, ...] = ()
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return fresh JSON-compatible fortification data, preserving nulls."""
        result: dict[str, Any] = {
            "status": self.status.value,
            "fortified_symbols": list(self.fortified_symbols),
            "fortifiable_symbols": (list(self.fortifiable_symbols) if self.fortifiable_symbols is not None else None),
            "coverage": self.coverage,
        }
        if self.evidence:
            result["evidence"] = list(self.evidence)
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True)
class AnalysisResult:
    """Hold a versioned analysis, its file metadata, checks and warnings."""

    schema_version: int
    file: str
    format: str
    architecture: str
    bits: int | None
    endianness: str
    needed_libraries: tuple[str, ...]
    checks: tuple[tuple[str, Finding | FortifyFinding], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a new JSON-compatible dictionary for the entire analysis."""
        return {
            "schema_version": self.schema_version,
            "file": self.file,
            "format": self.format,
            "architecture": self.architecture,
            "bits": self.bits,
            "endianness": self.endianness,
            "needed_libraries": list(self.needed_libraries),
            "checks": {name: finding.to_dict() for name, finding in self.checks},
            "warnings": list(self.warnings),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize this result to JSON using the optional indentation width."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        """Return a concise, plain-text rendering of the analysis."""
        lines = [f"{self.file}: {self.format} {self.architecture} ({self.bits or '?'}-bit, {self.endianness})"]
        for name, finding in self.checks:
            detail = f" ({finding.reason})" if finding.reason else ""
            lines.append(f"  {name}: {finding.status.value}{detail}")
        for warning in self.warnings:
            lines.append(f"  warning: {warning}")
        return "\n".join(lines)
