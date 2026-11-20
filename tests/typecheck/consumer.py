"""Static contract for a consumer of the installed distribution."""

from typing_extensions import assert_type

from libchecksec import (
    AddressInfoDict,
    AddressLocationDict,
    AnalysisResult,
    AnalysisResultDict,
    FindingDict,
    FortifyFindingDict,
    analyze,
)

result = analyze("program")
assert_type(result, AnalysisResult)
data = result.to_dict()
assert_type(data, AnalysisResultDict)
assert_type(data["needed_libraries"], list[str])
assert_type(data["checks"], dict[str, FindingDict | FortifyFindingDict])
assert_type(data["checks"]["nx"]["status"], str)
assert_type(data["addresses"], AddressInfoDict | None)
if data["addresses"] is not None:
    assert_type(data["addresses"]["entry"], AddressLocationDict)
    assert_type(data["addresses"]["entry"]["address"], int | None)

assert_type(result.to_json(indent=2), str)
assert_type(result.to_text(), str)

from libchecksec import AddressInfo, AddressLocation, Finding, FortifyFinding, Status
from libchecksec.addresses import analyze_addresses
from libchecksec.elf import analyze_elf
from libchecksec.pe import analyze_pe
import lief

finding = Finding(Status.ENABLED)
assert_type(finding.to_dict(), FindingDict)
fortify = FortifyFinding(Status.UNKNOWN)
assert_type(fortify.to_dict(), FortifyFindingDict)
location = AddressLocation(None, None)
assert_type(location.to_dict(), AddressLocationDict)
assert_type(AddressInfo(None, None, location, location).to_dict(), AddressInfoDict)
finding_data = finding.to_dict()
if "reason" in finding_data:
    assert_type(finding_data["reason"], str)


def check_formats(elf: lief.ELF.Binary, pe: lief.PE.Binary) -> None:
    """Check format-specific APIs accept parsed LIEF binary types.

    Args:
        elf: Parsed ELF input.
        pe: Parsed PE input.
    """
    assert_type(analyze_addresses(elf), AddressInfo)
    assert_type(analyze_addresses(pe), AddressInfo)
    assert_type(
        analyze_elf(elf), tuple[tuple[tuple[str, Finding | FortifyFinding], ...], tuple[str, ...], tuple[str, ...]]
    )
    assert_type(
        analyze_pe(pe), tuple[tuple[tuple[str, Finding | FortifyFinding], ...], tuple[str, ...], tuple[str, ...]]
    )
