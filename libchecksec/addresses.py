"""Report addresses from file metadata without loading or executing binaries."""

from __future__ import annotations

import lief

from ._lief import lief_text
from .models import AddressInfo, AddressLocation


def _unknown(reason: str) -> AddressLocation:
    """Return an unavailable address with an explanatory reason."""
    return AddressLocation(address=None, kind=None, symbol=None, reason=reason)


def _elf(binary: lief.ELF.Binary) -> AddressInfo:
    """Find static entry and main addresses in an ELF binary.

    Args:
        binary: Parsed ELF binary to inspect.

    Returns:
        Address metadata and reasons for unavailable values.
    """
    kind = binary.header.file_type
    if kind not in (lief.ELF.Header.FILE_TYPE.EXEC, lief.ELF.Header.FILE_TYPE.DYN):
        unavailable = _unknown("ELF type has no loadable process address")
        return AddressInfo(image_base=None, preferred_image_base=None, entry=unavailable, main=unavailable)

    # LIEF calculates the preferred mapping base from the loadable segments.
    if not any(segment.type == lief.ELF.Segment.TYPE.LOAD for segment in binary.segments):
        unavailable = _unknown("No loadable segments")
        return AddressInfo(image_base=None, preferred_image_base=None, entry=unavailable, main=unavailable)
    preferred = binary.imagebase
    dynamic = kind == lief.ELF.Header.FILE_TYPE.DYN
    base = None if dynamic else preferred
    address_kind = "image_relative" if dynamic else "virtual_address"
    entry_value = binary.header.entrypoint
    entry = (
        AddressLocation(
            address=entry_value - preferred if dynamic else entry_value, kind=address_kind, symbol=None, reason=None
        )
        if entry_value
        else _unknown("ELF entry point is zero")
    )

    # A defined function symbol is evidence of main; the entry point is not.
    mains = [
        s
        for s in binary.symbols
        if lief_text(s.name) == "main" and s.value and s.type == lief.ELF.Symbol.TYPE.FUNC and s.shndx != 0
    ]
    if mains:
        value = mains[0].value
        main = AddressLocation(
            address=value - preferred if dynamic else value, kind=address_kind, symbol="main", reason=None
        )
    else:
        main = _unknown("No defined nonzero main function symbol")
    return AddressInfo(image_base=base, preferred_image_base=preferred, entry=entry, main=main)


def _pe(binary: lief.PE.Binary) -> AddressInfo:
    """Find static entry and main addresses in a PE binary.

    Args:
        binary: Parsed PE binary to inspect.

    Returns:
        Address metadata and reasons for unavailable values.
    """
    # Header flags indicate whether the preferred base can be randomized.
    preferred = binary.optional_header.imagebase
    dynamic = binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    relocations = not binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.RELOCS_STRIPPED)
    relocatable = dynamic and relocations
    base = None if relocatable else preferred
    address_kind = "image_relative" if relocatable else "virtual_address"
    rva = binary.optional_header.addressof_entrypoint
    entry = (
        AddressLocation(address=rva if relocatable else preferred + rva, kind=address_kind, symbol=None, reason=None)
        if rva
        else _unknown("PE entry point is zero")
    )

    # COFF function symbol values are offsets within their section.
    main = _unknown("No defined COFF main function symbol")
    for symbol in binary.symbols:
        if (
            lief_text(symbol.name) not in ("main", "_main", "wmain", "_wmain")
            or symbol.is_undefined
            or not symbol.is_function
        ):
            continue
        sections = list(binary.sections)
        section_index = symbol.section_idx
        if section_index < 1 or section_index > len(sections):
            continue
        symbol_rva = sections[section_index - 1].virtual_address + symbol.value
        main = AddressLocation(
            address=symbol_rva if relocatable else preferred + symbol_rva,
            kind=address_kind,
            symbol=lief_text(symbol.name),
            reason=None,
        )
        break
    return AddressInfo(image_base=base, preferred_image_base=preferred, entry=entry, main=main)


def analyze_addresses(binary: lief.Binary) -> AddressInfo:
    """Find entry and main address metadata for a parsed binary.

    Args:
        binary: Parsed binary, supported for ELF and PE formats.

    Returns:
        Address metadata and reasons for unavailable values.
    """
    if isinstance(binary, lief.ELF.Binary):
        return _elf(binary)
    if isinstance(binary, lief.PE.Binary):
        return _pe(binary)
    unavailable = _unknown("Unsupported binary format")
    return AddressInfo(image_base=None, preferred_image_base=None, entry=unavailable, main=unavailable)
