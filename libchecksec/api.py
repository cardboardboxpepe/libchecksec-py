"""Parse explicitly named binaries and dispatch to format analyzers."""

from __future__ import annotations

from pathlib import Path
import struct

import lief

from .errors import ErrorParsingFailed, UnsupportedFormatError
from .models import AnalysisResult


def _parse(path: Path) -> lief.Binary:
    """Parse the regular file at path once and return its LIEF binary.

    Raise ErrorParsingFailed for inaccessible or malformed recognized inputs and
    UnsupportedFormatError for files without an ELF or PE signature.
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
        binary = lief.parse(str(path))
    except Exception as exc:
        raise ErrorParsingFailed(path) from exc
    if binary is None:
        raise ErrorParsingFailed(path)
    if not isinstance(binary, (lief.ELF.Binary, lief.PE.Binary)):
        raise UnsupportedFormatError(path)
    return binary


def _validate_elf_header(path: Path, header: bytes, size: int) -> None:
    """Validate the ELF header and declared tables against the file size."""
    if len(header) < 16 or header[4] not in (1, 2) or header[5] not in (1, 2) or header[6] != 1:
        raise ErrorParsingFailed(path, "Invalid ELF identification")
    bits = header[4]
    minimum = 52 if bits == 1 else 64
    if len(header) < minimum:
        raise ErrorParsingFailed(path, "Truncated ELF header")
    order = "<" if header[5] == 1 else ">"
    try:
        if bits == 1:
            phoff, shoff = struct.unpack_from(order + "II", header, 28)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHHH", header, 40)
        else:
            phoff, shoff = struct.unpack_from(order + "QQ", header, 32)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHHH", header, 52)
        version = struct.unpack_from(order + "I", header, 20)[0]
    except struct.error as exc:
        raise ErrorParsingFailed(path, "Invalid ELF header") from exc
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
    """Return format, architecture, bit width and byte order for binary."""
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

    The optional reference_libc is parsed once and used only for ELF analysis.
    Return an immutable AnalysisResult; input failures raise AnalysisError.
    """
    target_path = Path(path)
    binary = _parse(target_path)
    reference = _parse(Path(reference_libc)) if reference_libc is not None else None
    if reference is not None and not isinstance(reference, lief.ELF.Binary):
        raise UnsupportedFormatError(Path(reference_libc))

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
