"""Parse explicitly named binaries and dispatch to format analyzers."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Callable
from typing import cast

import lief

from .errors import ErrorParsingFailed, UnsupportedFormatError
from .models import AnalysisResult


def _parse(path: Path) -> lief.Binary:
    """Parse the regular file at path once and return its LIEF binary.

    Args:
        path: File to classify and parse.

    Returns:
        Parsed ELF or PE binary.

    Raises:
        ErrorParsingFailed: The file is inaccessible or malformed.
        UnsupportedFormatError: The file is not a supported ELF or PE.
    """
    try:
        if not path.is_file():
            raise ErrorParsingFailed(path, "Not an accessible regular file")
        with path.open("rb") as source:
            header = source.read(64)
            signature = header[:4]
            size = source.seek(0, 2)
    except OSError as exc:
        raise ErrorParsingFailed(path, "Not an accessible regular file") from exc

    # Classify from the signature before parsing so malformed inputs are distinct.
    if not (signature == b"\x7fELF" or signature.startswith(b"MZ")):
        raise UnsupportedFormatError(path)
    if signature == b"\x7fELF":
        _validate_elf_header(path, header, size)
    try:
        # LIEF's parse stub leaves PathLike unparameterized; this library passes
        # only strings and validates the returned format below.
        parse = cast(Callable[[str], lief.Binary | None], lief.parse)
        binary = parse(str(path))
    except Exception as exc:
        raise ErrorParsingFailed(path) from exc
    if binary is None:
        raise ErrorParsingFailed(path)
    if not isinstance(binary, (lief.ELF.Binary, lief.PE.Binary)):
        raise UnsupportedFormatError(path)
    return binary


def _validate_elf_header(path: Path, header: bytes, size: int) -> None:
    """Validate the ELF header and declared tables against the file size.

    Args:
        path: Input path used in errors.
        header: Initial bytes of the input file.
        size: Total input size in bytes.

    Raises:
        ErrorParsingFailed: The header or table bounds are invalid.
    """
    if len(header) < 16 or header[4] not in (1, 2) or header[5] not in (1, 2) or header[6] != 1:
        raise ErrorParsingFailed(path, "Invalid ELF identification")
    bits = header[4]
    minimum = 52 if bits == 1 else 64
    if len(header) < minimum:
        raise ErrorParsingFailed(path, "Truncated ELF header")
    byteorder = "little" if header[5] == 1 else "big"

    def read_int(offset: int, width: int) -> int:
        """Read a fixed-width integer from the validated header."""
        return int.from_bytes(header[offset : offset + width], byteorder)

    if bits == 1:
        phoff, shoff = read_int(28, 4), read_int(32, 4)
        table_offset = 40
    else:
        phoff, shoff = read_int(32, 8), read_int(40, 8)
        table_offset = 52
    ehsize, phentsize, phnum, shentsize, shnum = (read_int(table_offset + offset, 2) for offset in (0, 2, 4, 6, 8))
    version = read_int(20, 4)
    if version != 1 or ehsize < minimum or ehsize > size:
        raise ErrorParsingFailed(path, "Invalid ELF header")
    for offset, entry_size, count, min_entry in (
        (phoff, phentsize, phnum, 32 if bits == 1 else 56),
        (shoff, shentsize, shnum, 40 if bits == 1 else 64),
    ):
        if count and (not offset or entry_size < min_entry or offset + entry_size * count > size):
            raise ErrorParsingFailed(path, "Invalid ELF table bounds")


def _enum_name(value: object) -> str:
    """Return the enum name or a stable name for an unknown numeric value."""
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else f"unknown_{value}"


def _metadata(binary: lief.Binary) -> tuple[str, str, int | None, str]:
    """Extract format-independent metadata.

    Args:
        binary: Parsed ELF or PE binary.

    Returns:
        Format, architecture, optional bit width and byte order.

    Raises:
        TypeError: The parsed binary is not ELF or PE.
    """
    if isinstance(binary, lief.ELF.Binary):
        header = binary.header
        arch = _enum_name(header.machine_type).lower()
        arch = {"i386": "x86", "aarch64": "aarch64"}.get(arch, arch)
        bits = {"ELF32": 32, "ELF64": 64}.get(_enum_name(header.identity_class))
        endian = {"LSB": "little", "MSB": "big"}.get(_enum_name(header.identity_data), "unknown")
        return "ELF", arch, bits, endian
    if isinstance(binary, lief.PE.Binary):
        arch = _enum_name(binary.header.machine).lower()
        arch = {"amd64": "x86_64", "i386": "x86", "arm64": "aarch64"}.get(arch, arch)
        bits = {"PE32": 32, "PE32_PLUS": 64}.get(_enum_name(binary.optional_header.magic))
        return "PE", arch, bits, "little"
    raise TypeError("Unsupported parsed binary")


def analyze(path: Path | str, reference_libc: Path | str | None = None) -> AnalysisResult:
    """Analyze path once, optionally using the explicitly supplied ELF libc.

    Args:
        path: Path to the ELF or PE binary to analyze.
        reference_libc: Optional path to an ELF libc used for fortify coverage.
            It is parsed once and used only for ELF analysis.

    Returns:
        Immutable analysis result with metadata, findings, and warnings.

    Raises:
        ErrorParsingFailed: An input is inaccessible or cannot be parsed.
        UnsupportedFormatError: An input has an unsupported format, or the
            reference libc is not ELF.
    """
    target_path = Path(path)
    binary = _parse(target_path)
    reference = None
    if reference_libc is not None:
        reference_path = Path(reference_libc)
        reference = _parse(reference_path)
        if not isinstance(reference, lief.ELF.Binary):
            raise UnsupportedFormatError(reference_path)

    # Dispatch already-parsed binaries and collect format-independent metadata.
    if isinstance(binary, lief.ELF.Binary):
        from .elf import analyze_elf

        checks, needed, warnings = analyze_elf(binary, reference)
    elif isinstance(binary, lief.PE.Binary):
        from .pe import analyze_pe

        checks, needed, warnings = analyze_pe(binary)
    else:
        raise UnsupportedFormatError(target_path)
    from .addresses import analyze_addresses

    file_format, architecture, bits, endianness = _metadata(binary)
    addresses = analyze_addresses(binary)
    return AnalysisResult(
        1, str(target_path), file_format, architecture, bits, endianness, needed, checks, warnings, addresses
    )
