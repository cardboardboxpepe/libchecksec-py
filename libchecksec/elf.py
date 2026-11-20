"""Analyze mitigation evidence in an already parsed ELF binary."""

import lief

from .models import Finding, FortifyFinding, Status


def _relro(binary: lief.ELF.Binary) -> Finding:
    """Assess RELRO for binary and return its evidence."""
    if binary.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, reason="Relocatable object")
    if not binary.segments:
        return Finding(Status.NOT_APPLICABLE, reason="No program segments")
    if binary.get(lief.ELF.Segment.TYPE.GNU_RELRO) is None:
        return Finding(Status.ABSENT, ("GNU_RELRO segment absent",))

    # Full RELRO requires both a RELRO segment and immediate binding.
    tag = lief.ELF.DynamicEntry.TAG
    flags = lief.ELF.DynamicEntryFlags.FLAG
    evidence = ["GNU_RELRO segment present"]
    if binary.get(tag.BIND_NOW) is not None:
        evidence.append("DT_BIND_NOW")
    for entry_tag, flag, name in ((tag.FLAGS, flags.BIND_NOW, "DF_BIND_NOW"), (tag.FLAGS_1, flags.NOW, "DF_1_NOW")):
        entry = binary.get(entry_tag)
        if entry is not None and entry.has(flag):
            evidence.append(name)
    return Finding(Status.FULL if len(evidence) > 1 else Status.PARTIAL, tuple(evidence))


def _nx(binary: lief.ELF.Binary) -> Finding:
    """Assess the stack execution policy of binary and return evidence."""
    if binary.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, reason="Relocatable object")
    if not binary.segments:
        return Finding(Status.NOT_APPLICABLE, reason="No program segments")
    stack = binary.get(lief.ELF.Segment.TYPE.GNU_STACK)
    if stack is None:
        return Finding(Status.UNKNOWN, reason="GNU_STACK segment absent; stack policy depends on the platform")
    executable = stack.has(lief.ELF.Segment.FLAGS.X)
    return Finding(
        Status.DISABLED if executable else Status.ENABLED,
        ("GNU_STACK executable" if executable else "GNU_STACK non-executable",),
    )


def _pie(binary: lief.ELF.Binary) -> Finding:
    """Classify binary as PIE, shared object, relocatable, or fixed executable."""
    kind = binary.header.file_type
    if kind == lief.ELF.Header.FILE_TYPE.REL:
        return Finding(Status.NOT_APPLICABLE, ("ET_REL",), "Relocatable object")
    if kind != lief.ELF.Header.FILE_TYPE.DYN:
        return Finding(Status.DISABLED, (str(kind),))

    # An interpreter alone also appears in executable shared libraries.
    evidence = ["ET_DYN"]
    flags = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
    if flags is not None and flags.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
        evidence.append("DF_1_PIE")
    debug = binary.get(lief.ELF.DynamicEntry.TAG.DEBUG_TAG) is not None
    soname = binary.get(lief.ELF.DynamicEntry.TAG.SONAME)
    if binary.interpreter:
        evidence.append("PT_INTERP: " + binary.interpreter)
    if debug:
        evidence.append("DT_DEBUG")
    if soname is not None:
        evidence.append(f"DT_SONAME: {soname.name}")
    pie = (flags is not None and flags.has(lief.ELF.DynamicEntryFlags.FLAG.PIE)) or debug
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
    """Return presence and values of dynamic path entries with tag in binary."""
    entries = [entry for entry in binary.dynamic_entries if entry.tag == tag]
    values = tuple(str(getattr(entry, "rpath", getattr(entry, "runpath", ""))) for entry in entries)
    return Finding(Status.PRESENT if entries else Status.ABSENT, values)


def _fortify(binary: lief.ELF.Binary, reference_libc: lief.ELF.Binary | None) -> FortifyFinding:
    """Assess imported functions against reference_libc and return coverage as a percentage."""
    # Only undefined imported functions participate in the coverage denominator.
    imports = {s.name for s in binary.dynamic_symbols if s.imported and s.name and s.type == lief.ELF.Symbol.TYPE.FUNC}
    observed = {name for name in imports if name.startswith("__") and name.endswith("_chk")}
    if reference_libc is None:
        return FortifyFinding(
            Status.UNKNOWN,
            fortified_symbols=tuple(sorted(observed)),
            reason="No reference libc supplied; fortifiable imports are unknown",
        )
    fortified_libc = {
        s.name
        for s in reference_libc.dynamic_symbols
        if s.name.startswith("__") and s.name.endswith("_chk") and not s.imported
    }
    fortified = imports & fortified_libc
    bases = {name[2:-4] for name in fortified_libc}
    candidates = imports & (fortified_libc | bases)
    if not candidates:
        return FortifyFinding(
            Status.NOT_APPLICABLE,
            fortified_symbols=tuple(sorted(fortified)),
            fortifiable_symbols=(),
            reason="No fortifiable imported functions found in the reference libc",
        )
    return FortifyFinding(
        Status.ENABLED if fortified else Status.DISABLED,
        fortified_symbols=tuple(sorted(fortified)),
        fortifiable_symbols=tuple(sorted(candidates)),
        coverage=100.0 * len(fortified) / len(candidates),
    )


def analyze_elf(
    binary: lief.ELF.Binary, reference_libc: lief.ELF.Binary | None = None
) -> tuple[tuple[tuple[str, Finding | FortifyFinding], ...], tuple[str, ...], tuple[str, ...]]:
    """Analyze parsed binary and optional reference_libc; return checks, dependencies and warnings."""
    # Symbol evidence indicates a canary reference, not complete function coverage.
    names = {s.name for s in binary.symbols if s.name}
    canaries = tuple(sorted(names & {"__stack_chk_fail", "__stack_chk_fail_local", "__intel_security_cookie"}))
    canary = Finding(
        Status.ENABLED if canaries else Status.DISABLED,
        canaries,
        "Inferred from symbols; absence does not prove no stack protection",
    )
    symbols = tuple(s.name for s in binary.symtab_symbols if s.name)
    sym_finding = Finding(Status.PRESENT if symbols else Status.ABSENT, (f"{len(symbols)} named static symbols",))

    # Retain dependency order exactly as recorded in dynamic entries.
    needed = tuple(entry.name for entry in binary.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary))
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
