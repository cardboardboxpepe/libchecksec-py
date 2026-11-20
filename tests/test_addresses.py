"""Verify addresses against native ELF and PE file metadata."""

from pathlib import Path

import lief
import pytest

from libchecksec import analyze


@pytest.mark.parametrize("name,relative", [("pie_no", False), ("pie_pie", True), ("pie_dso", True)])
def test_elf_address_coordinates(binaries: Path, name: str, relative: bool) -> None:
    """Expose fixed virtual addresses or image offsets according to the ELF type."""
    path = binaries / "elf" / name
    binary = lief.parse(str(path))
    addresses = analyze(path).to_dict()["addresses"]
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
    """Find main independently of the executable's entry point."""
    path = binaries / "elf" / name
    binary = lief.parse(str(path))
    symbols = [s for s in binary.symbols if s.name == "main" and s.value and s.shndx != 0]
    assert symbols, "The main-address fixture must retain a main symbol"
    addresses = analyze(path).to_dict()["addresses"]
    relative = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    expected = symbols[0].value - binary.imagebase if relative else symbols[0].value
    assert addresses["main"]["address"] == expected
    assert addresses["main"]["symbol"] == "main"
    assert addresses["main"]["address"] != addresses["entry"]["address"]


def test_stripped_main_is_unknown(binaries: Path) -> None:
    """Return null with a reason when the file contains no discoverable main symbol."""
    addresses = analyze(binaries / "elf" / "symbols_disabled").to_dict()["addresses"]
    assert addresses["main"]["address"] is None
    assert addresses["main"]["reason"]


def test_relocatable_object_has_no_process_base(binaries: Path) -> None:
    """Avoid inventing loaded addresses for an unlinked relocatable object."""
    addresses = analyze(binaries / "elf" / "pie_rel").to_dict()["addresses"]
    assert addresses["image_base"] is None
    assert addresses["preferred_image_base"] is None
    assert addresses["entry"]["address"] is None
    assert addresses["main"]["address"] is None


@pytest.mark.parametrize("name", ["aslr_enabled.exe", "aslr_disabled.exe"])
def test_pe_image_base_and_entry(binaries: Path, name: str) -> None:
    """Retain the PE preferred base and distinguish RVA from fixed entry addresses."""
    path = binaries / "pe" / name
    binary = lief.parse(str(path))
    addresses = analyze(path).to_dict()["addresses"]
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
    """Resolve an actual COFF function symbol by adding its section RVA and offset."""
    import struct

    source = binaries / "pe" / name
    binary = lief.parse(str(source))
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
    reparsed = lief.parse(str(path))
    assert any(s.name == symbol_name and s.is_function for s in reparsed.symbols)
    addresses = analyze(path).to_dict()["addresses"]
    relative = addresses["image_base"] is None
    expected = section_rva + symbol_offset + (0 if relative else binary.optional_header.imagebase)
    assert addresses["main"]["address"] == expected
    assert addresses["main"]["symbol"] == symbol_name
