"""Preserve the original PE fixture coverage through the public API."""

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
@pytest.mark.parametrize(
    "name",
    [
        "nx",
        "canary",
        "dynamic_base",
        "aslr",
        "high_entropy_va",
        "safe_seh",
        "force_integrity",
        "guard_cf",
        "isolation",
        "authenticode",
    ],
)
def test_fixture_properties(binaries: Path, name: str, enabled: bool) -> None:
    """Return enabled or disabled for the corresponding compiler-created PE fixture.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
        enabled: Whether the fixture should report the property as enabled.
    """
    path = binaries / "pe" / f"{name}_{'enabled' if enabled else 'disabled'}.exe"
    result = analyze(path).to_dict()
    key = "stack_canary" if name == "canary" else name
    assert result["format"] == "PE"
    expected = "enabled" if enabled else ("absent" if name == "authenticode" else "disabled")
    assert result["checks"][key]["status"] == expected


def test_delay_imports_are_declared_dependencies(binaries: Path) -> None:
    """Include direct DLLs from both normal and delayed import tables in order.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """

    path = binaries / "pe" / "canary_disabled.exe"
    binary = _parse_fixture(str(path))
    assert isinstance(binary, lief.PE.Binary)
    expected = [item.name for item in binary.imports] + [item.name for item in binary.delay_imports]
    assert "WININET.dll" in expected
    assert analyze(path).to_dict()["needed_libraries"] == expected


def test_unparseable_certificate_is_unknown(binaries: Path, tmp_path: Path) -> None:
    """Distinguish malformed certificate data from an absent certificate table.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        tmp_path: Temporary directory supplied by pytest.
    """

    source = binaries / "pe" / "authenticode_enabled.exe"
    binary = _parse_fixture(str(source))
    assert isinstance(binary, lief.PE.Binary)
    certificate = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    data = bytearray(source.read_bytes())
    data[certificate.rva + 8] = 0
    path = tmp_path / "corrupt-certificate.exe"
    path.write_bytes(data)
    finding = analyze(path).to_dict()["checks"]["authenticode"]
    assert finding["status"] == "unknown"
    assert "certificate" in finding.get("reason", "").lower()
