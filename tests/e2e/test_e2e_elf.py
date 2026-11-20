"""Check observable ELF findings against the original binary fixtures."""

from pathlib import Path

import pytest

from libchecksec import analyze


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("name", ["nx", "canary", "rpath", "runpath", "symbols"])
def test_fixture_properties(binaries: Path, name: str, enabled: bool) -> None:
    """Analyze each positive/negative fixture and verify the corresponding status."""
    path = binaries / "elf" / f"{name}_{'enabled' if enabled else 'disabled'}"
    result = analyze(path).to_dict()
    key = "stack_canary" if name == "canary" else name
    status = result["checks"][key]["status"]
    assert status in ({"enabled", "present"} if enabled else {"disabled", "absent"})


@pytest.mark.parametrize("status", ["full", "partial", "no", "na"])
def test_relro(binaries: Path, status: str) -> None:
    """Preserve full, partial, absent, and inapplicable RELRO distinctions."""
    result = analyze(binaries / "elf" / f"relro_{status}").to_dict()
    expected = {"no": "absent", "na": "not_applicable"}.get(status, status)
    assert result["checks"]["relro"]["status"] == expected


def test_relro_flags_one(binaries: Path) -> None:
    """Recognize immediate binding through the FLAGS_1 dynamic entry."""
    result = analyze(binaries / "elf" / "relro_full_FLAGS_1").to_dict()
    assert result["checks"]["relro"]["status"] == "full"


@pytest.mark.parametrize(
    "kind,status", [("no", "disabled"), ("pie", "enabled"), ("dso", "dso"), ("rel", "not_applicable")]
)
def test_pie(binaries: Path, kind: str, status: str) -> None:
    """Distinguish PIE executables from shared objects and relocatable objects."""
    result = analyze(binaries / "elf" / f"pie_{kind}").to_dict()
    assert result["checks"]["pie"]["status"] == status


def test_fortify_with_reference(binaries: Path) -> None:
    """Count fortified and eligible imports using an explicitly supplied libc."""
    result = analyze(binaries / "elf" / "fortify_funcs", reference_libc=binaries / "elf" / "libc-2.27.so").to_dict()
    fortify = result["checks"]["fortify"]
    assert len(fortify["fortified_symbols"]) == 2
    assert len(fortify["fortifiable_symbols"]) == 3
    assert fortify["coverage"] == pytest.approx(100 * 2 / 3, abs=0.01)


def test_fortify_reference_does_not_leak(binaries: Path) -> None:
    """Ensure one call's explicit libc never affects another call's findings."""
    path = binaries / "elf" / "fortify_funcs"
    analyze(path, reference_libc=binaries / "elf" / "libc-2.27.so")
    fortify = analyze(path).to_dict()["checks"]["fortify"]
    assert fortify["status"] == "unknown"
    assert len(fortify["fortified_symbols"]) == 2
    assert fortify["fortifiable_symbols"] is None
    assert fortify["coverage"] is None


def test_runnable_libc_remains_shared_object(binaries: Path) -> None:
    """Avoid interpreting libc's interpreter segment as proof of PIE status."""
    result = analyze(binaries / "elf" / "libc-2.27.so").to_dict()
    assert result["checks"]["pie"]["status"] == "dso"


def test_interpreter_without_soname_is_ambiguous(binaries: Path) -> None:
    """Treat optional SONAME removal as ambiguous rather than proof of PIE."""
    import lief

    from libchecksec.elf import analyze_elf

    binary = lief.parse(str(binaries / "elf" / "libc-2.27.so"))
    binary.remove(lief.ELF.DynamicEntry.TAG.SONAME)
    checks, _, _ = analyze_elf(binary)
    assert dict(checks)["pie"].status.value == "unknown"


def test_no_program_segments_have_no_stack_policy(binaries: Path) -> None:
    """Do not infer runtime stack policy for an ELF without program segments."""
    import lief

    from libchecksec.elf import analyze_elf

    binary = lief.parse(str(binaries / "elf" / "relro_na"))
    assert not binary.segments
    binary.header.file_type = lief.ELF.Header.FILE_TYPE.NONE
    checks, _, _ = analyze_elf(binary)
    assert dict(checks)["nx"].status.value == "not_applicable"
