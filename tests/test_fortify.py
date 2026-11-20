"""Exercise fortification evidence and reference-based coverage independently."""

from types import SimpleNamespace

import lief
import pytest

from libchecksec.elf import _fortify
from libchecksec.models import Status


FUNC = lief.ELF.Symbol.TYPE.FUNC
IFUNC = lief.ELF.Symbol.TYPE.GNU_IFUNC
OBJECT = lief.ELF.Symbol.TYPE.OBJECT


def symbol(name: str, kind: lief.ELF.Symbol.TYPE = FUNC, imported: bool = False) -> SimpleNamespace:
    """Return a minimal symbol with its name, ELF type and import flag."""
    return SimpleNamespace(name=name, type=kind, imported=imported)


def binary(*symbols: SimpleNamespace, dynamic: tuple[SimpleNamespace, ...] = ()) -> SimpleNamespace:
    """Return a minimal binary with all symbols and its dynamic symbol table."""
    return SimpleNamespace(symbols=(*symbols, *dynamic), dynamic_symbols=dynamic)


@pytest.mark.parametrize("name", ["__printf_chk", "__memcpy_chk", "__fdelt_chk", "__nldbl___printf_chk"])
def test_checked_functions_enable_without_reference(name: str) -> None:
    """Recognize documented checked imports without a reference libc."""
    result = _fortify(binary(dynamic=(symbol(name, imported=True),)), None)
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
def test_unrelated_or_data_symbols_are_not_evidence(entry: SimpleNamespace) -> None:
    """Ignore unrelated names and non-function symbols."""
    result = _fortify(binary(entry), None)
    assert result.status == Status.UNKNOWN
    assert result.fortified_symbols == ()


def test_defined_functions_and_ifuncs_are_evidence() -> None:
    """Recognize defined functions and IFUNC symbols as positive evidence."""
    result = _fortify(binary(symbol("__printf_chk"), symbol("__memcpy_chk", IFUNC)), None)
    assert result.status == Status.ENABLED
    assert result.fortified_symbols == ("__memcpy_chk", "__printf_chk")


def test_reference_cannot_downgrade_observed_function() -> None:
    """Preserve positive evidence when a reference has no candidates."""
    result = _fortify(binary(symbol("__printf_chk")), binary())
    assert result.status == Status.ENABLED
    assert result.fortifiable_symbols == ()
    assert result.coverage is None


def test_coverage_counts_only_imports_and_reference_checked_definitions() -> None:
    """Exclude defined target functions from import coverage."""
    target = binary(symbol("__memcpy_chk"), dynamic=(symbol("printf", imported=True),))
    reference = binary(dynamic=(symbol("__printf_chk"), symbol("__memcpy_chk")))
    result = _fortify(target, reference)
    assert result.status == Status.ENABLED
    assert result.fortifiable_symbols == ("printf",)
    assert result.coverage == 0.0


def test_unfortified_import_is_disabled_with_reference() -> None:
    """Report zero coverage for an eligible unfortified import."""
    target = binary(dynamic=(symbol("printf", imported=True),))
    reference = binary(dynamic=(symbol("__printf_chk"),))
    result = _fortify(target, reference)
    assert result.status == Status.DISABLED
    assert result.coverage == 0.0


def test_long_double_alias_coverage() -> None:
    """Match checked long-double aliases to their corresponding import names."""
    target = binary(dynamic=(symbol("__nldbl_printf", imported=True),))
    reference = binary(dynamic=(symbol("__nldbl___printf_chk"),))
    result = _fortify(target, reference)
    assert result.status == Status.DISABLED
    assert result.fortifiable_symbols == ("__nldbl_printf",)
    assert result.coverage == 0.0
