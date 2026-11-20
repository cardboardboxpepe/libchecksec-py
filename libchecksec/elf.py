"""Analyze mitigation evidence in an already parsed ELF binary."""

import lief

from ._fortify_names import CHECKED_TO_BASE
from ._lief import lief_text
from .models import Finding, FortifyFinding, Status


def _relro(binary: lief.ELF.Binary) -> Finding:
    """Assess RELRO for a parsed ELF binary.

    Args:
        binary: Parsed ELF binary to inspect.

    Returns:
        The RELRO status and supporting evidence.
    """
    if binary.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, reason="Relocatable object")
    if not binary.segments:
        return Finding(Status.NOT_APPLICABLE, reason="No program segments")
    if not binary.has(lief.ELF.Segment.TYPE.GNU_RELRO):
        return Finding(Status.ABSENT, ("GNU_RELRO segment absent",))

    # Full RELRO requires both a RELRO segment and immediate binding.
    tag = lief.ELF.DynamicEntry.TAG
    flags = lief.ELF.DynamicEntryFlags.FLAG
    evidence = ["GNU_RELRO segment present"]
    if binary.has(tag.BIND_NOW):
        evidence.append("DT_BIND_NOW")
    for entry_tag, flag, name in ((tag.FLAGS, flags.BIND_NOW, "DF_BIND_NOW"), (tag.FLAGS_1, flags.NOW, "DF_1_NOW")):
        entry = binary.get(entry_tag)
        if isinstance(entry, lief.ELF.DynamicEntryFlags) and entry.has(flag):
            evidence.append(name)
    return Finding(Status.FULL if len(evidence) > 1 else Status.PARTIAL, tuple(evidence))


def _nx(binary: lief.ELF.Binary) -> Finding:
    """Assess the stack execution policy of a parsed ELF binary.

    Args:
        binary: Parsed ELF binary to inspect.

    Returns:
        The stack execution status and supporting evidence.
    """
    if binary.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, reason="Relocatable object")
    if not binary.segments:
        return Finding(Status.NOT_APPLICABLE, reason="No program segments")
    if not binary.has(lief.ELF.Segment.TYPE.GNU_STACK):
        return Finding(Status.UNKNOWN, reason="GNU_STACK segment absent; stack policy depends on the platform")
    stack = binary.get(lief.ELF.Segment.TYPE.GNU_STACK)
    executable = stack.has(lief.ELF.Segment.FLAGS.X)
    return Finding(
        Status.DISABLED if executable else Status.ENABLED,
        ("GNU_STACK executable" if executable else "GNU_STACK non-executable",),
    )


def _pie(binary: lief.ELF.Binary) -> Finding:
    """Classify a parsed ELF binary as PIE, shared object, relocatable, or fixed executable.

    Args:
        binary: Parsed ELF binary to inspect.

    Returns:
        The classification and supporting evidence.
    """
    kind = binary.header.file_type
    if kind == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, ("ET_REL",), "Relocatable object")
    if kind != lief.ELF.Header.FILE_TYPE.DYN:
        return Finding(Status.DISABLED, (str(kind),))

    # An interpreter alone also appears in executable shared libraries.
    evidence = ["ET_DYN"]
    flags = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
    if isinstance(flags, lief.ELF.DynamicEntryFlags) and flags.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
        evidence.append("DF_1_PIE")
    debug = binary.has(lief.ELF.DynamicEntry.TAG.DEBUG_TAG)
    soname = binary.get(lief.ELF.DynamicEntry.TAG.SONAME) if binary.has(lief.ELF.DynamicEntry.TAG.SONAME) else None
    if binary.interpreter:
        evidence.append("PT_INTERP: " + binary.interpreter)
    if debug:
        evidence.append("DT_DEBUG")
    if isinstance(soname, lief.ELF.DynamicSharedObject):
        evidence.append(f"DT_SONAME: {lief_text(soname.name)}")
    pie = (isinstance(flags, lief.ELF.DynamicEntryFlags) and flags.has(lief.ELF.DynamicEntryFlags.FLAG.PIE)) or debug
    if pie:
        return Finding(Status.ENABLED, tuple(evidence))
    if binary.interpreter and soname is None:
        return Finding(
            Status.UNKNOWN,
            tuple(evidence),
            "Interpreter alone does not distinguish PIE from an executable shared library",
        )
    return Finding(Status.DSO, tuple(evidence))


def _path(binary: lief.ELF.Binary, tag: lief.ELF.DynamicEntry.TAG) -> Finding:
    """Find dynamic path entries with a given tag.

    Args:
        binary: Parsed ELF binary to inspect.
        tag: Dynamic entry tag to match.

    Returns:
        The presence and values of matching entries.
    """
    entries = [entry for entry in binary.dynamic_entries if entry.tag == tag]
    values = tuple(str(getattr(entry, "rpath", getattr(entry, "runpath", ""))) for entry in entries)
    return Finding(Status.PRESENT if entries else Status.ABSENT, values)


def _fortify(binary: lief.ELF.Binary, reference_libc: lief.ELF.Binary | None) -> FortifyFinding:
    """Assess fortified functions and optional reference-based import coverage.

    Args:
        binary: Parsed ELF binary to inspect.
        reference_libc: Optional parsed libc used to identify fortifiable imports.

    Returns:
        The fortification status, observed symbols, and available coverage.
    """
    function_types = (lief.ELF.Symbol.TYPE.FUNC, lief.ELF.Symbol.TYPE.GNU_IFUNC)
    # Positive evidence includes definitions as well as imports, but never data symbols.
    observed = {
        lief_text(s.name) for s in binary.symbols if s.type in function_types and lief_text(s.name) in CHECKED_TO_BASE
    }
    if reference_libc is None:
        return FortifyFinding(
            Status.ENABLED if observed else Status.UNKNOWN,
            fortified_symbols=tuple(sorted(observed)),
            reason="No reference libc supplied; fortifiable import coverage is unknown",
        )

    # Coverage counts only imported functions with checked variants in the reference.
    imports = {lief_text(s.name) for s in binary.dynamic_symbols if s.imported and s.name and s.type in function_types}
    checked = {
        lief_text(s.name)
        for s in reference_libc.dynamic_symbols
        if lief_text(s.name) in CHECKED_TO_BASE and not s.imported and s.type in function_types
    }
    candidates = imports & (checked | {CHECKED_TO_BASE[name] for name in checked})
    if not candidates:
        return FortifyFinding(
            Status.ENABLED if observed else Status.NOT_APPLICABLE,
            fortified_symbols=tuple(sorted(observed)),
            fortifiable_symbols=(),
            reason="No fortifiable imported functions found in the reference libc",
        )
    return FortifyFinding(
        Status.ENABLED if observed else Status.DISABLED,
        fortified_symbols=tuple(sorted(observed)),
        fortifiable_symbols=tuple(sorted(candidates)),
        coverage=100.0 * len(imports & checked) / len(candidates),
    )


def analyze_elf(
    binary: lief.ELF.Binary, reference_libc: lief.ELF.Binary | None = None
) -> tuple[tuple[tuple[str, Finding | FortifyFinding], ...], tuple[str, ...], tuple[str, ...]]:
    """Analyze mitigation evidence in a parsed ELF binary.

    Args:
        binary: Parsed ELF binary to inspect.
        reference_libc: Optional parsed libc used to assess fortification coverage.

    Returns:
        A tuple of named findings, dependencies, and warnings.
    """
    # Symbol evidence indicates a canary reference, not complete function coverage.
    names = {lief_text(s.name) for s in binary.symbols if s.name}
    canaries = tuple(sorted(names & {"__stack_chk_fail", "__stack_chk_fail_local", "__intel_security_cookie"}))
    canary = Finding(
        Status.ENABLED if canaries else Status.DISABLED,
        canaries,
        "Inferred from symbols; absence does not prove no stack protection",
    )
    symbols = tuple(lief_text(s.name) for s in binary.symtab_symbols if s.name)
    sym_finding = Finding(Status.PRESENT if symbols else Status.ABSENT, (f"{len(symbols)} named static symbols",))

    # Retain dependency order exactly as recorded in dynamic entries.
    needed = tuple(
        lief_text(entry.name) for entry in binary.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary)
    )
    checks = (
        ("relro", _relro(binary)),
        ("stack_canary", canary),
        ("nx", _nx(binary)),
        ("pie", _pie(binary)),
        ("rpath", _path(binary, lief.ELF.DynamicEntry.TAG.RPATH)),
        ("runpath", _path(binary, lief.ELF.DynamicEntry.TAG.RUNPATH)),
        ("symbols", sym_finding),
        ("fortify", _fortify(binary, reference_libc)),
    )
    return checks, needed, ()
