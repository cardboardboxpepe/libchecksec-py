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
class AddressLocation:
    """Describe an address, its interpretation, associated symbol and reason."""

    address: int | None
    kind: str | None
    symbol: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the address and its attributes as JSON-compatible values."""
        return {"address": self.address, "kind": self.kind, "symbol": self.symbol, "reason": self.reason}


@dataclass(frozen=True)
class AddressInfo:
    """Describe the image base, preferred base, entry point and main symbol."""

    image_base: int | None
    preferred_image_base: int | None
    entry: AddressLocation
    main: AddressLocation

    def to_dict(self) -> dict[str, Any]:
        """Return fresh JSON-compatible address metadata, preserving nulls."""
        return {
            "image_base": self.image_base,
            "preferred_image_base": self.preferred_image_base,
            "entry": self.entry.to_dict(),
            "main": self.main.to_dict(),
        }


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
    addresses: AddressInfo | None = None

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
            "addresses": self.addresses.to_dict() if self.addresses is not None else None,
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
        if self.addresses is not None:

            def format_address(value: int | None) -> str:
                """Return value as hexadecimal or an unavailable marker."""
                return hex(value) if value is not None else "unknown"

            lines.append(f"  image base: {format_address(self.addresses.image_base)}")
            lines.append(f"  preferred image base: {format_address(self.addresses.preferred_image_base)}")
            for label, location in (("entry", self.addresses.entry), ("main", self.addresses.main)):
                detail = location.kind or location.reason or "unknown"
                lines.append(f"  {label}: {format_address(location.address)} ({detail})")
        for warning in self.warnings:
            lines.append(f"  warning: {warning}")
        return "\n".join(lines)
