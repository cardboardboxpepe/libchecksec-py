"""Exercise fortification evidence and reference-based coverage independently."""

from dataclasses import dataclass
from typing import cast

import lief
import pytest

# These white-box tests intentionally exercise the internal fortify check.
from libchecksec.elf import _fortify  # pyright: ignore[reportPrivateUsage]
from libchecksec.models import FortifyFinding, Status

FUNC = lief.ELF.Symbol.TYPE.FUNC
IFUNC = lief.ELF.Symbol.TYPE.GNU_IFUNC
OBJECT = lief.ELF.Symbol.TYPE.OBJECT


@dataclass
class SymbolStub:
    """Provide the symbol attributes read by the fortify analyzer."""

    name: str
    type: lief.ELF.Symbol.TYPE
    imported: bool


@dataclass
class BinaryStub:
    """Provide symbol tables read by the fortify analyzer."""

    symbols: tuple[SymbolStub, ...]
    dynamic_symbols: tuple[SymbolStub, ...]


def fortify(binary: BinaryStub, reference: BinaryStub | None) -> FortifyFinding:
    """Call the native binary analyzer with the minimal test doubles.

    Args:
        binary: Target with the symbol attributes used by fortify.
        reference: Optional libc with the same test-double interface.
    """
    # The doubles provide the attributes read by _fortify; LIEF types are native.
    target = cast(lief.ELF.Binary, binary)
    libc = cast(lief.ELF.Binary, reference) if reference is not None else None
    return _fortify(target, libc)


def symbol(name: str, kind: lief.ELF.Symbol.TYPE = FUNC, imported: bool = False) -> SymbolStub:
    """Return a minimal symbol with its name, ELF type and import flag.

    Args:
        name: Name of the fixture or symbol under test.
        kind: ELF symbol type.
        imported: Whether the symbol is imported.
    """
    return SymbolStub(name=name, type=kind, imported=imported)


def binary(*symbols: SymbolStub, dynamic: tuple[SymbolStub, ...] = ()) -> BinaryStub:
    """Return a minimal binary with all symbols and its dynamic symbol table.

    Args:
        dynamic: Symbols to include in the dynamic symbol table.
        *symbols: Symbols to include in the binary.
    """
    return BinaryStub(symbols=(*symbols, *dynamic), dynamic_symbols=dynamic)


@pytest.mark.parametrize("name", ["__printf_chk", "__memcpy_chk", "__fdelt_chk", "__nldbl___printf_chk"])
def test_checked_functions_enable_without_reference(name: str) -> None:
    """Recognize documented checked imports without a reference libc.

    Args:
        name: Name of the fixture or symbol under test.
    """
    result = fortify(binary(dynamic=(symbol(name, imported=True),)), None)
    assert result.status == Status.ENABLED
    assert result.fortified_symbols == (name,)
    assert result.coverage is None


@pytest.mark.parametrize(
    "entry",
    [
        symbol("__custom_chk"),
        symbol("__nldbl___custom_chk"),
        symbol("__stack_chk_fail"),
        symbol("__open_chk"),
        symbol("__mq_open_chk"),
        symbol("__printf_chk", OBJECT),
    ],
)
def test_unrelated_or_data_symbols_are_not_evidence(entry: SymbolStub) -> None:
    """Ignore unrelated names and non-function symbols.

    Args:
        entry: Symbol entry under test.
    """
    result = fortify(binary(entry), None)
    assert result.status == Status.UNKNOWN
    assert result.fortified_symbols == ()


def test_defined_functions_and_ifuncs_are_evidence() -> None:
    """Recognize defined functions and IFUNC symbols as positive evidence."""
    result = fortify(binary(symbol("__printf_chk"), symbol("__memcpy_chk", IFUNC)), None)
    assert result.status == Status.ENABLED
    assert result.fortified_symbols == ("__memcpy_chk", "__printf_chk")


def test_reference_cannot_downgrade_observed_function() -> None:
    """Preserve positive evidence when a reference has no candidates."""
    result = fortify(binary(symbol("__printf_chk")), binary())
    assert result.status == Status.ENABLED
    assert result.fortifiable_symbols == ()
    assert result.coverage is None


def test_coverage_counts_only_imports_and_reference_checked_definitions() -> None:
    """Exclude defined target functions from import coverage."""
    target = binary(symbol("__memcpy_chk"), dynamic=(symbol("printf", imported=True),))
    reference = binary(dynamic=(symbol("__printf_chk"), symbol("__memcpy_chk")))
    result = fortify(target, reference)
    assert result.status == Status.ENABLED
    assert result.fortifiable_symbols == ("printf",)
    assert result.coverage == 0.0


def test_unfortified_import_is_disabled_with_reference() -> None:
    """Report zero coverage for an eligible unfortified import."""
    target = binary(dynamic=(symbol("printf", imported=True),))
    reference = binary(dynamic=(symbol("__printf_chk"),))
    result = fortify(target, reference)
    assert result.status == Status.DISABLED
    assert result.coverage == 0.0


def test_long_double_alias_coverage() -> None:
    """Match checked long-double aliases to their corresponding import names."""
    target = binary(dynamic=(symbol("__nldbl_printf", imported=True),))
    reference = binary(dynamic=(symbol("__nldbl___printf_chk"),))
    result = fortify(target, reference)
    assert result.status == Status.DISABLED
    assert result.fortifiable_symbols == ("__nldbl_printf",)
    assert result.coverage == 0.0
