"""Check observable ELF findings against the original binary fixtures."""

from pathlib import Path
from collections.abc import Callable
from typing import cast

import lief
import pytest

from libchecksec import analyze


def _parse_fixture(path: str) -> lief.Binary:
    """Parse a fixture through LIEF's string input boundary."""
    # LIEF's stub leaves PathLike unparameterized; this helper passes strings.
    parse = cast(Callable[[str], lief.Binary | None], lief.parse)
    binary = parse(path)
    assert binary is not None
    return binary


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("name", ["nx", "canary", "rpath", "runpath", "symbols"])
def test_fixture_properties(binaries: Path, name: str, enabled: bool) -> None:
    """Analyze each positive/negative fixture and verify the corresponding status.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
        enabled: Whether the fixture should report the property as enabled.
    """
    path = binaries / "elf" / f"{name}_{'enabled' if enabled else 'disabled'}"
    result = analyze(path).to_dict()
    key = "stack_canary" if name == "canary" else name
    status = result["checks"][key]["status"]
    assert status in ({"enabled", "present"} if enabled else {"disabled", "absent"})


@pytest.mark.parametrize("status", ["full", "partial", "no", "na"])
def test_relro(binaries: Path, status: str) -> None:
    """Preserve full, partial, absent, and inapplicable RELRO distinctions.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        status: Expected status of the finding.
    """
    result = analyze(binaries / "elf" / f"relro_{status}").to_dict()
    expected = {"no": "absent", "na": "not_applicable"}.get(status, status)
    assert result["checks"]["relro"]["status"] == expected


def test_relro_flags_one(binaries: Path) -> None:
    """Recognize immediate binding through the FLAGS_1 dynamic entry.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    result = analyze(binaries / "elf" / "relro_full_FLAGS_1").to_dict()
    assert result["checks"]["relro"]["status"] == "full"


@pytest.mark.parametrize(
    "kind,status", [("no", "disabled"), ("pie", "enabled"), ("dso", "dso"), ("rel", "not_applicable")]
)
def test_pie(binaries: Path, kind: str, status: str) -> None:
    """Distinguish PIE executables from shared objects and relocatable objects.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        kind: Input or ELF kind under test.
        status: Expected status of the finding.
    """
    result = analyze(binaries / "elf" / f"pie_{kind}").to_dict()
    assert result["checks"]["pie"]["status"] == status


def test_fortify_with_reference(binaries: Path) -> None:
    """Count fortified and eligible imports using an explicitly supplied libc.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    result = analyze(binaries / "elf" / "fortify_funcs", reference_libc=binaries / "elf" / "libc-2.27.so").to_dict()
    fortify = result["checks"]["fortify"]
    assert "fortified_symbols" in fortify
    assert len(fortify["fortified_symbols"]) == 2
    assert fortify["fortifiable_symbols"] is not None
    assert len(fortify["fortifiable_symbols"]) == 3
    assert fortify["coverage"] is not None
    assert abs(fortify["coverage"] - 100 * 2 / 3) <= 0.01


def test_fortify_reference_does_not_leak(binaries: Path) -> None:
    """Ensure one call's explicit libc never affects another call's findings.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    path = binaries / "elf" / "fortify_funcs"
    analyze(path, reference_libc=binaries / "elf" / "libc-2.27.so")
    fortify = analyze(path).to_dict()["checks"]["fortify"]
    assert fortify["status"] == "enabled"
    assert "fortified_symbols" in fortify
    assert len(fortify["fortified_symbols"]) == 2
    assert fortify["fortifiable_symbols"] is None
    assert fortify["coverage"] is None


def test_runnable_libc_remains_shared_object(binaries: Path) -> None:
    """Avoid interpreting libc's interpreter segment as proof of PIE status.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    result = analyze(binaries / "elf" / "libc-2.27.so").to_dict()
    assert result["checks"]["pie"]["status"] == "dso"


def test_interpreter_without_soname_is_ambiguous(binaries: Path) -> None:
    """Treat optional SONAME removal as ambiguous rather than proof of PIE.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    from libchecksec.elf import analyze_elf

    binary = _parse_fixture(str(binaries / "elf" / "libc-2.27.so"))
    assert isinstance(binary, lief.ELF.Binary)
    binary.remove(lief.ELF.DynamicEntry.TAG.SONAME)
    checks, _, _ = analyze_elf(binary)
    assert dict(checks)["pie"].status.value == "unknown"


def test_no_program_segments_have_no_stack_policy(binaries: Path) -> None:
    """Do not infer runtime stack policy for an ELF without program segments.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    from libchecksec.elf import analyze_elf

    binary = _parse_fixture(str(binaries / "elf" / "relro_na"))
    assert isinstance(binary, lief.ELF.Binary)
    assert not binary.segments
    binary.header.file_type = lief.ELF.Header.FILE_TYPE.NONE
    checks, _, _ = analyze_elf(binary)
    assert dict(checks)["nx"].status.value == "not_applicable"
