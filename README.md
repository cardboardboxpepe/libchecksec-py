# libchecksec-py

A Python library for inspecting ELF and PE binary security properties with
[LIEF](https://lief.re/). It reports static evidence and uncertainty rather
than executing a file or resolving its dependencies.

## Installation

Python 3.10 through 3.13 is supported. LIEF 0.17.2 is the only runtime
dependency.

```sh
git clone https://github.com/cardboardboxpepe/libchecksec-py.git
cd libchecksec-py
python -m pip install .
```

## Library API

```python
from libchecksec import AnalysisError, analyze

try:
    result = analyze("./program")
    print(result.to_text())
    data = result.to_dict()
    print(result.to_json(indent=2))
except AnalysisError as error:
    print(error)
```

`analyze` accepts a path to one ELF or PE file and returns an immutable
`AnalysisResult`. Its JSON-compatible dictionary has `schema_version`, `file`,
`format`, `architecture`, `bits`, `endianness`, `needed_libraries`, `checks`,
and `warnings`, and `addresses`. Each check contains a `status`, evidence, and sometimes a
reason. Statuses include `enabled`, `disabled`, `unknown`, `not_applicable`,
`full`, `partial`, `absent`, `present`, and `dso`; their interpretation depends
on the check. The output schema is versioned independently of the package.

For ELF, `needed_libraries` lists direct `DT_NEEDED` entries. For PE, it lists
ordinary imported library names followed by delay-import library names, in
table order. Neither list is a transitive dependency resolution.

### Address metadata

The `addresses` field reports `image_base`, `preferred_image_base`, `entry`,
and `main`. Entry and main each contain an `address`, a `kind`, a `symbol`,
and a `reason`; unavailable values are `null`. Addresses marked
`image_relative` are offsets from the image base, while `virtual_address`
values use the static image's preferred mapping. A main address requires a
defined main function symbol; it is not guessed from the entry point.

These values come from the file, not a running process. For relocatable images,
the actual runtime image base is unknown and `image_base` is `null`. Even when
a preferred base is reported, a loader may map an image elsewhere; in
particular PE images can be rebased when relocation information permits it.

### Fortification

ELF fortify analysis can use an explicitly supplied reference libc:

```python
result = analyze("./program", reference_libc="/path/to/libc.so.6")
```

Without a reference, fortifiable symbols and coverage are unknown (`null` in
JSON), even when fortified imports are visible. A reference library should
match the target's environment; the analyzer does not discover the target's
libc automatically. Fortification coverage is based on imported symbol
information, not a proof that all relevant code is protected.

## Command line

```sh
libchecksec ./program
libchecksec --json ./program ./other-program
libchecksec --reference-libc /path/to/libc.so.6 ./program
```

The CLI accepts explicit files, prints successful results even when another
file fails, and exits nonzero if any file cannot be analyzed. JSON output is
an object for one successful requested file and an array for multiple files.

## Scope and limitations

ELF checks include RELRO, stack canary evidence, NX, PIE, RPATH, RUNPATH,
symbols, and fortification. PE checks cover relevant header flags, stack-cookie
and SafeSEH evidence, and Authenticode presence. Signature presence is not
certificate-chain trust verification. Some findings depend on symbol or header
evidence and cannot establish complete protection. Unknown and inapplicable
results are distinct from disabled or absent results. This is a static analysis;
it does not verify runtime loader behavior or security of the execution
environment. LIEF can emit parser diagnostics to stderr for malformed inputs.
Parsing uses native code without built-in sandboxing or resource limits; callers
handling untrusted files should isolate the parser and bound resources.

## Attribution and license

This project derives from [checksec.py](https://github.com/Wenzel/checksec.py)
by Mathieu Tarral and its contributors. It remains licensed under the
[GNU General Public License, version 3 only](LICENSE).
