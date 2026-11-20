"""Analyze mitigation evidence in an already parsed PE binary."""

import lief

from ._lief import lief_text
from .models import Finding, FortifyFinding, Status


def _boolean(enabled: bool, evidence: str) -> Finding:
    """Return a finding for enabled with the supplied evidence description."""
    return Finding(Status.ENABLED if enabled else Status.DISABLED, (evidence,))


def _signature(binary: lief.PE.Binary) -> Finding:
    """Check Authenticode integrity without asserting certificate trust.

    Args:
        binary: Parsed PE binary to inspect.

    Returns:
        The signature integrity status and supporting evidence.
    """
    if not binary.has_signatures:
        directory = next(
            (entry for entry in binary.data_directories if entry.type == lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE),
            None,
        )
        if directory is not None and (directory.rva or directory.size):
            return Finding(
                Status.UNKNOWN,
                reason="Certificate table exists but no signature was parsed; no trust-chain validation performed",
            )
        return Finding(Status.ABSENT, ("No Authenticode signature",), "No trust-chain validation performed")
    try:
        result = binary.verify_signature()
    except Exception as exc:
        return Finding(
            Status.UNKNOWN, reason=f"Signature verification failed: {exc}; no trust-chain validation performed"
        )
    return Finding(
        Status.ENABLED if result == lief.PE.Signature.VERIFICATION_FLAGS.OK else Status.DISABLED,
        (f"LIEF signature verification: {result}",),
        "No trust-chain validation performed",
    )


def analyze_pe(
    binary: lief.PE.Binary,
) -> tuple[tuple[tuple[str, Finding | FortifyFinding], ...], tuple[str, ...], tuple[str, ...]]:
    """Analyze mitigation evidence in a parsed PE binary.

    Args:
        binary: Parsed PE binary to inspect.

    Returns:
        A tuple of named findings, imported libraries, and warnings.
    """
    # Header flags supply the base mitigation and compatibility indications.
    optional = binary.optional_header
    header = binary.header
    characteristic = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
    header_flag = lief.PE.Header.CHARACTERISTICS
    dynamic = optional.has(characteristic.DYNAMIC_BASE)
    relocations = not header.has_characteristic(header_flag.RELOCS_STRIPPED)
    aslr = dynamic and relocations
    seh = not optional.has(characteristic.NO_SEH)
    load = binary.load_configuration
    cookie = bool(getattr(load, "security_cookie", 0))

    # SafeSEH applies only to x86; a table and count require SEH to be enabled.
    if header.machine != lief.PE.Header.MACHINE_TYPES.I386:
        safe_seh = Finding(Status.NOT_APPLICABLE, (f"Machine: {header.machine}",), "SafeSEH applies to x86")
    else:
        table = getattr(load, "se_handler_table", 0)
        count = getattr(load, "se_handler_count", 0)
        safe_seh = _boolean(
            bool(seh and table and count), f"SEH={seh}, handler table={table:#x}, handler count={count}"
        )

    # Signature validation concerns the embedded signature and digest, not trust.
    checks = (
        ("nx", _boolean(optional.has(characteristic.NX_COMPAT), f"NX_COMPAT={optional.has(characteristic.NX_COMPAT)}")),
        ("stack_canary", _boolean(cookie, f"Security cookie present={cookie}")),
        ("aslr", _boolean(aslr, f"DYNAMIC_BASE={dynamic}, relocations available={relocations}")),
        ("dynamic_base", _boolean(dynamic, f"DYNAMIC_BASE={dynamic}")),
        (
            "high_entropy_va",
            _boolean(
                optional.has(characteristic.HIGH_ENTROPY_VA),
                f"HIGH_ENTROPY_VA={optional.has(characteristic.HIGH_ENTROPY_VA)}",
            ),
        ),
        ("seh", _boolean(seh, f"NO_SEH={not seh}")),
        ("safe_seh", safe_seh),
        (
            "force_integrity",
            _boolean(
                optional.has(characteristic.FORCE_INTEGRITY),
                f"FORCE_INTEGRITY={optional.has(characteristic.FORCE_INTEGRITY)}",
            ),
        ),
        (
            "guard_cf",
            _boolean(
                aslr and optional.has(characteristic.GUARD_CF),
                f"ASLR={aslr}, GUARD_CF={optional.has(characteristic.GUARD_CF)}",
            ),
        ),
        (
            "isolation",
            _boolean(
                not optional.has(characteristic.NO_ISOLATION),
                f"NO_ISOLATION={optional.has(characteristic.NO_ISOLATION)}",
            ),
        ),
        ("authenticode", _signature(binary)),
    )
    return (
        checks,
        tuple(lief_text(item.name) for item in binary.imports)
        + tuple(lief_text(item.name) for item in binary.delay_imports),
        (),
    )
