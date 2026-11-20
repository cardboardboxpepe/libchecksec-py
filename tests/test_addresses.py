"""Verify addresses against native ELF and PE file metadata."""

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


@pytest.mark.parametrize("name,relative", [("pie_no", False), ("pie_pie", True), ("pie_dso", True)])
def test_elf_address_coordinates(binaries: Path, name: str, relative: bool) -> None:
    """Expose fixed virtual addresses or image offsets according to the ELF type.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
        relative: Whether the expected address is image-relative.
    """
    path = binaries / "elf" / name
    binary = _parse_fixture(str(path))
    assert isinstance(binary, lief.ELF.Binary)
    addresses = analyze(path).to_dict()["addresses"]
    assert addresses is not None
    preferred = binary.imagebase
    assert addresses["preferred_image_base"] == preferred
    assert addresses["image_base"] == (None if relative else preferred)
    entry = addresses["entry"]
    expected = binary.header.entrypoint - preferred if relative else binary.header.entrypoint
    if binary.header.entrypoint:
        assert entry["address"] == expected
        assert entry["kind"] == ("image_relative" if relative else "virtual_address")
    else:
        assert entry["address"] is None
        assert entry["reason"]


@pytest.mark.parametrize("name", ["symbols_enabled", "fortify_funcs", "pie_no"])
def test_elf_main_from_defined_symbol(binaries: Path, name: str) -> None:
    """Find main independently of the executable's entry point.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
    """
    path = binaries / "elf" / name
    binary = _parse_fixture(str(path))
    assert isinstance(binary, lief.ELF.Binary)
    symbols = [s for s in binary.symbols if s.name == "main" and s.value and s.shndx != 0]
    assert symbols, "The main-address fixture must retain a main symbol"
    addresses = analyze(path).to_dict()["addresses"]
    assert addresses is not None
    relative = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    expected = symbols[0].value - binary.imagebase if relative else symbols[0].value
    assert addresses["main"]["address"] == expected
    assert addresses["main"]["symbol"] == "main"
    assert addresses["main"]["address"] != addresses["entry"]["address"]


def test_stripped_main_is_unknown(binaries: Path) -> None:
    """Return null with a reason when the file contains no discoverable main symbol.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    addresses = analyze(binaries / "elf" / "symbols_disabled").to_dict()["addresses"]
    assert addresses is not None
    assert addresses["main"]["address"] is None
    assert addresses["main"]["reason"]


def test_relocatable_object_has_no_process_base(binaries: Path) -> None:
    """Avoid inventing loaded addresses for an unlinked relocatable object.

    Args:
        binaries: Directory containing the pinned binary fixtures.
    """
    addresses = analyze(binaries / "elf" / "pie_rel").to_dict()["addresses"]
    assert addresses is not None
    assert addresses["image_base"] is None
    assert addresses["preferred_image_base"] is None
    assert addresses["entry"]["address"] is None
    assert addresses["main"]["address"] is None


@pytest.mark.parametrize("name", ["aslr_enabled.exe", "aslr_disabled.exe"])
def test_pe_image_base_and_entry(binaries: Path, name: str) -> None:
    """Retain the PE preferred base and distinguish RVA from fixed entry addresses.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        name: Name of the fixture or symbol under test.
    """
    path = binaries / "pe" / name
    binary = _parse_fixture(str(path))
    assert isinstance(binary, lief.PE.Binary)
    addresses = analyze(path).to_dict()["addresses"]
    assert addresses is not None
    preferred = binary.optional_header.imagebase
    dynamic = binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    relocations = not binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.RELOCS_STRIPPED)
    relative = dynamic and relocations
    rva = binary.optional_header.addressof_entrypoint
    assert addresses["preferred_image_base"] == preferred
    assert addresses["image_base"] == (None if relative else preferred)
    assert addresses["entry"]["address"] == (rva if relative else preferred + rva)
    assert addresses["entry"]["kind"] == ("image_relative" if relative else "virtual_address")


@pytest.mark.parametrize("name", ["aslr_enabled.exe", "aslr_disabled.exe"])
@pytest.mark.parametrize("symbol_name", ["main", "_main", "wmain", "_wmain"])
def test_pe_coff_main_is_section_relative(binaries: Path, tmp_path: Path, name: str, symbol_name: str) -> None:
    """Resolve an actual COFF function symbol by adding its section RVA and offset.

    Args:
        binaries: Directory containing the pinned binary fixtures.
        tmp_path: Temporary directory supplied by pytest.
        name: Name of the fixture or symbol under test.
        symbol_name: COFF symbol to resolve.
    """
    import struct

    source = binaries / "pe" / name
    binary = _parse_fixture(str(source))
    assert isinstance(binary, lief.PE.Binary)
    section_index = next(i for i, section in enumerate(binary.sections, start=1) if section.name == ".text")
    section_rva = list(binary.sections)[section_index - 1].virtual_address
    symbol_offset = 16
    data = bytearray(source.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff_offset = pe_offset + 4
    table_offset = len(data)
    struct.pack_into("<II", data, coff_offset + 8, table_offset, 1)
    data.extend(struct.pack("<8sIhHBB", symbol_name.encode("ascii"), symbol_offset, section_index, 0x20, 2, 0))
    data.extend(struct.pack("<I", 4))
    path = tmp_path / name
    path.write_bytes(data)
    reparsed = _parse_fixture(str(path))
    assert isinstance(reparsed, lief.PE.Binary)
    assert any(s.name == symbol_name and s.is_function for s in reparsed.symbols)
    addresses = analyze(path).to_dict()["addresses"]
    assert addresses is not None
    relative = addresses["image_base"] is None
    expected = section_rva + symbol_offset + (0 if relative else binary.optional_header.imagebase)
    assert addresses["main"]["address"] == expected
    assert addresses["main"]["symbol"] == symbol_name
