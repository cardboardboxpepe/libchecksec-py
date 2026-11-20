# Output reference

These examples were captured with libchecksec-py 0.10.2 and LIEF 0.17.2 (`0.17.2-aa2b617f`). Captured on 2026-11-20, the host's `/usr/bin/bash` was GNU Bash 5.3.20(1)-release and had SHA-256 `4387a4c2e6503752e83d8139d2a2a4c92113268614856b4706212fdab6c14dc3`. Results, paths, dependencies, and addresses vary with the files and environment. Analysis parses files; it does not execute Bash or the target.

## Command line

```
libchecksec [-h] [--json] [--reference-libc REFERENCE_LIBC] files [files ...]
```

- Supply one or more explicit ELF or PE paths. Use `--` before paths beginning with `-`.
- `-h` / `--help` prints argparse help and exits successfully without analyzing files.
- `--json` selects JSON; otherwise each successful result is printed as text.
- `--reference-libc PATH` supplies an explicit ELF reference for fortify analysis. It is parsed for each requested file, including PE files, but affects ELF fortify only. An inaccessible, invalid, or non-ELF reference fails that analysis. Choose a libc matching the target; none is discovered automatically.

The captured `python -m libchecksec --help` output is:

```text
usage: __main__.py [-h] [--json] [--reference-libc REFERENCE_LIBC]
                   files [files ...]

Analyze binary security properties

positional arguments:
  files                 ELF or PE files to analyze

options:
  -h, --help            show this help message and exit
  --json                output JSON
  --reference-libc REFERENCE_LIBC
                        explicit ELF libc for fortify coverage
```

For example:

```sh
libchecksec --json /usr/bin/bash
libchecksec --json --reference-libc /usr/lib64/libc.so.6 /usr/bin/bash
libchecksec --json -- ./-named-file
```

For one requested file, successful JSON is an object. For multiple requested files it is an array of successful results, in input order, even if only one succeeds. A failed single file or a batch with no successes prints `[]` in JSON mode. Errors go to stderr and successful results remain on stdout. The exit status is 0 if all files succeed and 1 if any analysis fails; argparse errors exit 2. In text mode a failed file contributes no stdout result. For example, analyzing `missing-binary` alone produced exit status 1, no text stdout, and this stderr:

```text
Not an accessible regular file: missing-binary
```

The equivalent JSON command produced `[]` on stdout with the same stderr and exit status. A mixed success/failure batch returns an array containing the successful results and exits 1. Parser diagnostics from LIEF may also appear on stderr.

## Captured ELF JSON

`libchecksec --json /usr/bin/bash` produced the following complete object:

```json
{
  "schema_version": 1,
  "file": "/usr/bin/bash",
  "format": "ELF",
  "architecture": "x86_64",
  "bits": 64,
  "endianness": "little",
  "needed_libraries": [
    "libreadline.so.8",
    "libc.so.6"
  ],
  "checks": {
    "relro": {
      "status": "full",
      "evidence": [
        "GNU_RELRO segment present",
        "DF_BIND_NOW",
        "DF_1_NOW"
      ]
    },
    "stack_canary": {
      "status": "enabled",
      "evidence": [
        "__stack_chk_fail"
      ],
      "reason": "Inferred from symbols; absence does not prove no stack protection"
    },
    "nx": {
      "status": "enabled",
      "evidence": [
        "GNU_STACK non-executable"
      ]
    },
    "pie": {
      "status": "enabled",
      "evidence": [
        "ET_DYN",
        "DF_1_PIE",
        "PT_INTERP: /lib64/ld-linux-x86-64.so.2",
        "DT_DEBUG"
      ]
    },
    "rpath": {
      "status": "absent",
      "evidence": []
    },
    "runpath": {
      "status": "absent",
      "evidence": []
    },
    "symbols": {
      "status": "absent",
      "evidence": [
        "0 named static symbols"
      ]
    },
    "fortify": {
      "status": "unknown",
      "fortified_symbols": [
        "__fdelt_chk",
        "__fprintf_chk",
        "__longjmp_chk",
        "__mbsrtowcs_chk",
        "__memcpy_chk",
        "__memmove_chk",
        "__memset_chk",
        "__printf_chk",
        "__snprintf_chk",
        "__sprintf_chk",
        "__strcpy_chk",
        "__strncpy_chk",
        "__vfprintf_chk",
        "__vsnprintf_chk",
        "__wcsrtombs_chk"
      ],
      "fortifiable_symbols": null,
      "coverage": null,
      "reason": "No reference libc supplied; fortifiable imports are unknown"
    }
  },
  "warnings": [],
  "addresses": {
    "image_base": null,
    "preferred_image_base": 0,
    "entry": {
      "address": 265920,
      "kind": "image_relative",
      "symbol": null,
      "reason": null
    },
    "main": {
      "address": null,
      "kind": null,
      "symbol": null,
      "reason": "No defined nonzero main function symbol"
    }
  }
}
```

With `--reference-libc /usr/lib64/libc.so.6`, the same file produced:

```json
{
  "schema_version": 1,
  "file": "/usr/bin/bash",
  "format": "ELF",
  "architecture": "x86_64",
  "bits": 64,
  "endianness": "little",
  "needed_libraries": [
    "libreadline.so.8",
    "libc.so.6"
  ],
  "checks": {
    "relro": {
      "status": "full",
      "evidence": [
        "GNU_RELRO segment present",
        "DF_BIND_NOW",
        "DF_1_NOW"
      ]
    },
    "stack_canary": {
      "status": "enabled",
      "evidence": [
        "__stack_chk_fail"
      ],
      "reason": "Inferred from symbols; absence does not prove no stack protection"
    },
    "nx": {
      "status": "enabled",
      "evidence": [
        "GNU_STACK non-executable"
      ]
    },
    "pie": {
      "status": "enabled",
      "evidence": [
        "ET_DYN",
        "DF_1_PIE",
        "PT_INTERP: /lib64/ld-linux-x86-64.so.2",
        "DT_DEBUG"
      ]
    },
    "rpath": {
      "status": "absent",
      "evidence": []
    },
    "runpath": {
      "status": "absent",
      "evidence": []
    },
    "symbols": {
      "status": "absent",
      "evidence": [
        "0 named static symbols"
      ]
    },
    "fortify": {
      "status": "enabled",
      "fortified_symbols": [
        "__fdelt_chk",
        "__fprintf_chk",
        "__longjmp_chk",
        "__mbsrtowcs_chk",
        "__memcpy_chk",
        "__memmove_chk",
        "__memset_chk",
        "__printf_chk",
        "__snprintf_chk",
        "__sprintf_chk",
        "__strcpy_chk",
        "__strncpy_chk",
        "__vfprintf_chk",
        "__vsnprintf_chk",
        "__wcsrtombs_chk"
      ],
      "fortifiable_symbols": [
        "__fdelt_chk",
        "__fprintf_chk",
        "__longjmp_chk",
        "__mbsrtowcs_chk",
        "__memcpy_chk",
        "__memmove_chk",
        "__memset_chk",
        "__printf_chk",
        "__snprintf_chk",
        "__sprintf_chk",
        "__strcpy_chk",
        "__strncpy_chk",
        "__vfprintf_chk",
        "__vsnprintf_chk",
        "__wcsrtombs_chk",
        "confstr",
        "fgets_unlocked",
        "getcwd",
        "getgroups",
        "gethostname",
        "mbsnrtowcs",
        "mbsrtowcs",
        "mbstowcs",
        "memcpy",
        "memmove",
        "memset",
        "read",
        "readlink",
        "stpcpy",
        "strcat",
        "strcpy",
        "strncpy",
        "wcrtomb",
        "wcsnrtombs",
        "wcsrtombs",
        "wctomb"
      ],
      "coverage": 41.666666666666664
    }
  },
  "warnings": [],
  "addresses": {
    "image_base": null,
    "preferred_image_base": 0,
    "entry": {
      "address": 265920,
      "kind": "image_relative",
      "symbol": null,
      "reason": null
    },
    "main": {
      "address": null,
      "kind": null,
      "symbol": null,
      "reason": "No defined nonzero main function symbol"
    }
  }
}
```

Without a reference, observed imports matching `__*_chk` are listed but the set of fortifiable imports and coverage are unknown. With a reference, defined `__*_chk` symbols in that ELF are matched against imported functions and their base names. Coverage is `100 * fortified imports / fortifiable imports`; it is an import-based measure, not proof of complete protection. If there are no matching candidates, status is `not_applicable`, the candidate list is empty, and coverage is null. A matching reference can therefore change the status, lists, and coverage.

## Captured PE JSON

After initializing the fixture submodule, `libchecksec --json tests/binaries/pe/aslr_enabled.exe` produced:

```json
{
  "schema_version": 1,
  "file": "tests/binaries/pe/aslr_enabled.exe",
  "format": "PE",
  "architecture": "x86",
  "bits": 32,
  "endianness": "little",
  "needed_libraries": [
    "VCRUNTIME140D.dll",
    "ucrtbased.dll",
    "KERNEL32.dll"
  ],
  "checks": {
    "nx": {
      "status": "enabled",
      "evidence": [
        "NX_COMPAT=True"
      ]
    },
    "stack_canary": {
      "status": "enabled",
      "evidence": [
        "Security cookie present=True"
      ]
    },
    "aslr": {
      "status": "enabled",
      "evidence": [
        "DYNAMIC_BASE=True, relocations available=True"
      ]
    },
    "dynamic_base": {
      "status": "enabled",
      "evidence": [
        "DYNAMIC_BASE=True"
      ]
    },
    "high_entropy_va": {
      "status": "disabled",
      "evidence": [
        "HIGH_ENTROPY_VA=False"
      ]
    },
    "seh": {
      "status": "enabled",
      "evidence": [
        "NO_SEH=False"
      ]
    },
    "safe_seh": {
      "status": "enabled",
      "evidence": [
        "SEH=True, handler table=0x407720, handler count=2"
      ]
    },
    "force_integrity": {
      "status": "disabled",
      "evidence": [
        "FORCE_INTEGRITY=False"
      ]
    },
    "guard_cf": {
      "status": "disabled",
      "evidence": [
        "ASLR=True, GUARD_CF=False"
      ]
    },
    "isolation": {
      "status": "enabled",
      "evidence": [
        "NO_ISOLATION=False"
      ]
    },
    "authenticode": {
      "status": "absent",
      "evidence": [
        "No Authenticode signature"
      ],
      "reason": "No trust-chain validation performed"
    }
  },
  "warnings": [],
  "addresses": {
    "image_base": null,
    "preferred_image_base": 4194304,
    "entry": {
      "address": 4606,
      "kind": "image_relative",
      "symbol": null,
      "reason": null
    },
    "main": {
      "address": null,
      "kind": null,
      "symbol": null,
      "reason": "No defined COFF main function symbol"
    }
  }
}
```

## Result schema

`AnalysisResult.to_dict()` and `to_json()` expose the same versioned structure as CLI JSON. Schema version 1 contains:

- `schema_version`: integer schema version; `file`: path string normalized by `str(Path(path))`; `format`: `ELF` or `PE`; `architecture`: LIEF machine name normalized by the API; `bits`: 32, 64, or null when unavailable; `endianness`: `little`, `big`, or `unknown`.
- `needed_libraries`: direct ELF `DT_NEEDED` names, or PE ordinary imports followed by delay imports, in table order. These are not resolved transitively.
- `checks`: format-specific named findings described below. A normal finding always has `status` and an `evidence` array, possibly empty; `reason` is omitted when unavailable.
- ELF `fortify` instead always has `status`, `fortified_symbols`, `fortifiable_symbols`, and `coverage`. The latter two can be null; `evidence` is omitted when empty and `reason` is omitted when unavailable. Coverage is a percentage number when known.
- `warnings`: an array, currently empty for both backends. `addresses`: an address object, or null if an `AnalysisResult` has no address information. The analyzer supplies an address object for supported formats.

Text output prints file metadata, check statuses and any reasons, addresses, and warnings. It omits detailed evidence, dependency lists, fortify symbol lists, and coverage. JSON numbers are decimal; text renders addresses in hexadecimal. These samples show one outcome per check; the alternatives below do not all occur on one file.

### Addresses

`addresses` contains `image_base`, `preferred_image_base`, `entry`, and `main`. Each location always contains `address`, `kind`, `symbol`, and `reason`, with null for unavailable values. `image_relative` is an offset from the runtime image base; `virtual_address` is a static virtual address. `image_base` is null when the analyzer identifies a relocatable image; `preferred_image_base` is the preferred static mapping, not a measured runtime base. Loaders may map images elsewhere, including rebasing PE images. ELF without loadable segments or a loadable process type has unavailable addresses. A zero entry point is unavailable. `main` requires a defined ELF function symbol named `main` or a defined PE COFF function symbol named `main`, `_main`, `wmain`, or `_wmain`; it is not inferred from entry. In this stripped Bash capture `main` is null and its PIE runtime base is unknown.

### Known symbols and fixed addresses

These are captured `addresses` objects only, from two ELF fixtures; the remaining result fields are omitted here. Initialize the fixture submodule with `git submodule update --init tests/binaries`, then reproduce either excerpt without running the target:

```python
import json
from libchecksec import analyze

path = "tests/binaries/elf/pie_no"  # Or "tests/binaries/elf/symbols_enabled".
print(json.dumps(analyze(path).to_dict()["addresses"], indent=2))
```

The fixed-address `tests/binaries/elf/pie_no` fixture has a known `main` and virtual addresses:

```json
{
  "image_base": 4194304,
  "preferred_image_base": 4194304,
  "entry": {
    "address": 4198544,
    "kind": "virtual_address",
    "symbol": null,
    "reason": null
  },
  "main": {
    "address": 4198774,
    "kind": "virtual_address",
    "symbol": "main",
    "reason": null
  }
}
```

The PIE `tests/binaries/elf/symbols_enabled` fixture also has a known `main`, but reports image-relative offsets and an unknown runtime base:

```json
{
  "image_base": null,
  "preferred_image_base": 0,
  "entry": {
    "address": 4256,
    "kind": "image_relative",
    "symbol": null,
    "reason": null
  },
  "main": {
    "address": 4489,
    "kind": "image_relative",
    "symbol": "main",
    "reason": null
  }
}
```

## Checks and possible statuses

These are the statuses emitted by the current analyzers, not a claim that the underlying mitigation is complete or active at runtime.

### ELF

- `relro`: `full` for GNU_RELRO plus immediate binding, `partial` for GNU_RELRO without it, `absent` without GNU_RELRO, or `not_applicable` for relocatable objects or files without program segments.
- `stack_canary`: `enabled` if a recognized canary symbol is present, otherwise `disabled`; missing symbol evidence does not prove absence of stack protection.
- `nx`: `enabled` for non-executable GNU_STACK, `disabled` for executable GNU_STACK, `unknown` when GNU_STACK is missing, or `not_applicable` for relocatable objects or files without segments. This assesses stack policy.
- `pie`: `enabled` for ET_DYN with DF_1_PIE or DT_DEBUG; `unknown` for ET_DYN with an interpreter alone and no SONAME; `dso` for other ET_DYN; `not_applicable` for ET_REL; otherwise `disabled`.
- `rpath` and `runpath`: `present` or `absent`, with dynamic path values in evidence.
- `symbols`: `present` or `absent` based on named static symbols; evidence gives the count.
- `fortify`: `unknown` without a reference, `not_applicable` when no imported candidates match the reference, `enabled` when candidates include fortified imports, or `disabled` when candidates exist but none are fortified.

### PE

- `nx`, `stack_canary`, `dynamic_base`, `high_entropy_va`, `seh`, `force_integrity`, and `isolation` are `enabled` or `disabled`, based respectively on NX_COMPAT, a load-configuration security cookie, DYNAMIC_BASE, HIGH_ENTROPY_VA, absence of NO_SEH, FORCE_INTEGRITY, and absence of NO_ISOLATION.
- `aslr` is `enabled` only when DYNAMIC_BASE is set and relocations are not marked stripped; otherwise `disabled`. `guard_cf` is `enabled` only when that ASLR condition and GUARD_CF are both set; otherwise `disabled`.
- `safe_seh` is `enabled` on x86 when SEH is enabled and a handler table and count exist, `disabled` otherwise on x86, and `not_applicable` on other machines.
- `authenticode` is `absent` without a signature or certificate table, `unknown` if a certificate table exists but no signature was parsed or verification raises an exception, `enabled` if LIEF signature verification returns OK, and `disabled` for another verification result. This does not validate certificate-chain trust.
