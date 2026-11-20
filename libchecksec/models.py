"""Immutable, transport-independent analysis results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import TypedDict


class _FindingRequired(TypedDict):
    """JSON-compatible representation of a standard finding."""

    status: str
    evidence: list[str]


class _FindingOptional(TypedDict, total=False):
    """Optional fields in a standard finding."""

    reason: str


class FindingDict(_FindingRequired, _FindingOptional):
    """JSON-compatible finding; reason is present only when available."""


class _FortifyRequired(TypedDict):
    """Required fields in a fortification finding."""

    status: str
    fortified_symbols: list[str]
    fortifiable_symbols: list[str] | None
    coverage: float | None


class _FortifyOptional(TypedDict, total=False):
    """Optional fields in a fortification finding."""

    evidence: list[str]
    reason: str


class FortifyFindingDict(_FortifyRequired, _FortifyOptional):
    """JSON-compatible fortification finding; evidence and reason are optional."""


class AddressLocationDict(TypedDict):
    """JSON-compatible address location, retaining unavailable values as null."""

    address: int | None
    kind: str | None
    symbol: str | None
    reason: str | None


class AddressInfoDict(TypedDict):
    """JSON-compatible image bases and entry and main locations."""

    image_base: int | None
    preferred_image_base: int | None
    entry: AddressLocationDict
    main: AddressLocationDict


class AnalysisResultDict(TypedDict):
    """Versioned JSON-compatible analysis and its metadata and findings."""

    schema_version: int
    file: str
    format: str
    architecture: str
    bits: int | None
    endianness: str
    needed_libraries: list[str]
    checks: dict[str, FindingDict | FortifyFindingDict]
    warnings: list[str]
    addresses: AddressInfoDict | None


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
    """Describe a check by status, supporting evidence and optional reason.

    Attributes:
        status: Outcome of the check.
        evidence: Statements supporting the outcome.
        reason: Explanation when the outcome needs qualification.
    """

    status: Status
    evidence: tuple[str, ...] = ()
    reason: str | None = None

    def to_dict(self) -> FindingDict:
        """Return a fresh JSON-compatible representation of this finding."""
        result: FindingDict = {"status": self.status.value, "evidence": list(self.evidence)}
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True)
class FortifyFinding:
    """Describe fortification status and symbol coverage.

    Attributes:
        status: Outcome of the fortification check.
        fortified_symbols: Detected fortified symbols.
        fortifiable_symbols: Symbols eligible for fortification, if known.
        coverage: Percentage of eligible imported symbols fortified, if known;
            statically defined target symbols are excluded.
        evidence: Statements supporting the outcome.
        reason: Explanation when the outcome needs qualification.
    """

    status: Status
    fortified_symbols: tuple[str, ...] = ()
    fortifiable_symbols: tuple[str, ...] | None = None
    coverage: float | None = None
    evidence: tuple[str, ...] = ()
    reason: str | None = None

    def to_dict(self) -> FortifyFindingDict:
        """Return fresh JSON-compatible fortification data, preserving nulls."""
        result: FortifyFindingDict = {
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
    """Describe an address and its interpretation.

    Attributes:
        address: Numeric address, or None when unavailable.
        kind: Interpretation of the address, if known.
        symbol: Associated symbol, if known.
        reason: Explanation when the location is unavailable or qualified.
    """

    address: int | None
    kind: str | None
    symbol: str | None = None
    reason: str | None = None

    def to_dict(self) -> AddressLocationDict:
        """Return the address and its attributes as JSON-compatible values."""
        return {"address": self.address, "kind": self.kind, "symbol": self.symbol, "reason": self.reason}


@dataclass(frozen=True)
class AddressInfo:
    """Describe image bases and significant locations.

    Attributes:
        image_base: Statically inferred image base, if known; runtime relocation is unavailable.
        preferred_image_base: Preferred image base from the file, if known.
        entry: Executable entry point.
        main: Main symbol location.
    """

    image_base: int | None
    preferred_image_base: int | None
    entry: AddressLocation
    main: AddressLocation

    def to_dict(self) -> AddressInfoDict:
        """Return fresh JSON-compatible address metadata, preserving nulls."""
        return {
            "image_base": self.image_base,
            "preferred_image_base": self.preferred_image_base,
            "entry": self.entry.to_dict(),
            "main": self.main.to_dict(),
        }


@dataclass(frozen=True)
class AnalysisResult:
    """Hold a versioned analysis, its file metadata, checks and warnings.

    Attributes:
        schema_version: Version of the serialized result schema.
        file: Path of the analyzed file.
        format: Binary format name.
        architecture: Processor architecture name.
        bits: Binary bit width, if known.
        endianness: Byte order name.
        needed_libraries: Names of required shared libraries.
        checks: Named security findings in output order.
        warnings: Analysis warnings.
        addresses: Address metadata, if available.
    """

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

    def to_dict(self) -> AnalysisResultDict:
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
        """Serialize this result to JSON.

        Args:
            indent: JSON indentation width, or None for compact output.

        Returns:
            Serialized JSON representation of the result.
        """
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
