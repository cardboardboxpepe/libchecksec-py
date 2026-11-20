"""Exercise public serialization, failure handling, and library isolation."""

import json
import logging
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from collections.abc import Callable
from typing import cast
from unittest.mock import patch

import lief
import pytest

from libchecksec import analyze
from libchecksec.errors import ErrorParsingFailed, UnsupportedFormatError


def _parse_fixture(path: str) -> lief.Binary:
    """Parse a fixture through LIEF's string input boundary."""
    # LIEF's stub leaves PathLike unparameterized; this helper passes strings.
    parse = cast(Callable[[str], lief.Binary | None], lief.parse)
    binary = parse(path)
    assert binary is not None
    return binary


@pytest.mark.parametrize("name", ["default", "pie_rel", "pie_dso"])
def test_json_contract(binaries: Path, name: str) -> None:
    """Return JSON primitives without leaking mutable or native parser state.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
    """
    result = analyze(binaries / "elf" / name)
    data = result.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["schema_version"] == 1
    assert data["format"] == "ELF"
    assert data["bits"] in (32, 64)
    assert data["endianness"] in ("little", "big")
    assert isinstance(data["architecture"], str)
    assert isinstance(data["needed_libraries"], list)
    assert isinstance(data["warnings"], list)
    for finding in data["checks"].values():
        assert isinstance(finding["status"], str)
        assert isinstance(finding.get("evidence", []), list)

    # A consumer can freely edit serialized data without modifying the result.
    data["warnings"].append("consumer change")
    data["checks"]["nx"]["status"] = "consumer change"
    assert "consumer change" not in json.dumps(result.to_dict())
    with pytest.raises((FrozenInstanceError, AttributeError)):
        setattr(result, "file", "changed")


def test_dependencies_preserve_dynamic_order(binaries: Path) -> None:
    """Match all direct DT_NEEDED strings and their original order.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    path = binaries / "elf" / "default"
    binary = _parse_fixture(str(path))
    assert isinstance(binary, lief.ELF.Binary)
    expected = [entry.name for entry in binary.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary)]
    assert analyze(path).to_dict()["needed_libraries"] == expected


def test_analyze_parses_target_once(binaries: Path) -> None:
    """Avoid redundant parsing within a single ordinary analysis call.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    path = binaries / "elf" / "default"
    with patch.object(lief, "parse", wraps=cast(Callable[[str], lief.Binary | None], lief.parse)) as parser:
        analyze(path)
    assert parser.call_count == 1


def test_core_has_no_process_or_logging_side_effects(binaries: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Analyze a binary without executing programs or configuring root logging.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        capsys: Pytest capture fixture for stdout and stderr.
    """
    root = logging.getLogger()
    before = (root.level, tuple(root.handlers))
    with patch.object(subprocess, "Popen", side_effect=AssertionError("process launch")), patch.object(
        logging, "basicConfig", side_effect=AssertionError("logging configuration")
    ):
        analyze(binaries / "elf" / "default")
    assert (root.level, tuple(root.handlers)) == before
    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.parametrize("kind", ["text", "truncated"])
def test_invalid_binary_is_controlled(tmp_path: Path, kind: str) -> None:
    """Reject unsupported data and truncated ELF inputs with public errors.

    Args:
        tmp_path: Temporary directory supplied by pytest.
        kind: Input or ELF kind under test.
    """
    path = tmp_path / kind
    path.write_bytes(b"plain text\n" if kind == "text" else b"\x7fELF\x02\x01")
    with pytest.raises((ErrorParsingFailed, UnsupportedFormatError)):
        analyze(path)


def test_missing_and_directory_paths(tmp_path: Path) -> None:
    """Preserve meaningful filesystem exceptions for unavailable input paths.

    Args:
        tmp_path: Temporary directory supplied by pytest.
    """
    with pytest.raises(ErrorParsingFailed):
        analyze(tmp_path / "missing")
    with pytest.raises(ErrorParsingFailed):
        analyze(tmp_path)


def test_invalid_reference_is_not_silently_ignored(binaries: Path, tmp_path: Path) -> None:
    """Fail an explicit invalid libc request instead of reporting normal coverage.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        tmp_path: Temporary directory supplied by pytest.
    """
    path = tmp_path / "libc"
    path.write_text("not an ELF", encoding="utf-8")
    with pytest.raises((ErrorParsingFailed, UnsupportedFormatError, ValueError)):
        analyze(binaries / "elf" / "default", reference_libc=path)


def test_cli_json_and_failure_exit(binaries: Path) -> None:
    """Print valid JSON for successful inputs and return nonzero on a missing file.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    command = [sys.executable, "-m", "libchecksec", "--json", str(binaries / "elf" / "default")]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)
    failed = subprocess.run(
        [sys.executable, "-m", "libchecksec", str(binaries / "missing")], capture_output=True, text=True, check=False
    )
    assert failed.returncode != 0
    assert "Traceback" not in failed.stderr


@pytest.mark.parametrize("offset,replacement", [(4, b"\x03"), (5, b"\x03"), (18, b"\xff\xff")])
def test_unknown_elf_metadata_is_controlled(binaries: Path, tmp_path: Path, offset: int, replacement: bytes) -> None:
    """Reject invalid encodings or report unknown machines without leaking enum errors.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        tmp_path: Temporary directory supplied by pytest.
        offset: Byte offset of the metadata to replace.
        replacement: Bytes used to replace the selected metadata.
    """
    data = bytearray((binaries / "elf" / "default").read_bytes())
    data[offset : offset + len(replacement)] = replacement
    path = tmp_path / "unusual-elf"
    path.write_bytes(data)
    try:
        result = analyze(path).to_dict()
    except (ErrorParsingFailed, UnsupportedFormatError):
        return
    assert isinstance(result["architecture"], str)
    assert result["architecture"]


def test_invalid_utf8_dependency_name_is_json_safe(binaries: Path, tmp_path: Path) -> None:
    """Normalize invalid dependency-name bytes from real binary files.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        tmp_path: Temporary directory supplied by pytest.
    """
    source = binaries / "elf/default"
    binary = _parse_fixture(str(source))
    assert isinstance(binary, lief.ELF.Binary)
    data = bytearray(source.read_bytes())
    original_name = binary.libraries[0]
    assert isinstance(original_name, str)
    name = original_name.encode("ascii")
    offset = data.index(name + b"\0")
    data[offset] = 0xFF
    path = tmp_path / "invalid-elf"
    path.write_bytes(data)
    parsed = _parse_fixture(str(path))
    assert isinstance(parsed, lief.ELF.Binary)
    name = parsed.libraries[0]
    assert isinstance(name, bytes)
    result = analyze(path).to_dict()
    assert result["needed_libraries"][0].startswith("\\xff")
    json.dumps(result)


@pytest.mark.parametrize("name,expected", [("valid", "valid"), (b"caf\xc3\xa9", "caf\u00e9"), (b"bad\xff", "bad\\xff")])
def test_lief_text_normalizes_names(name: str | bytes, expected: str) -> None:
    """Preserve text and decode valid or malformed LIEF name bytes.

    Args:
        name: Name returned by LIEF.
        expected: Expected JSON-compatible text.
    """
    from libchecksec._lief import lief_text

    assert lief_text(name) == expected
