"""Minimal command-line interface for explicit binary analysis."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import AnalysisError, analyze


def main(argv: Sequence[str] | None = None) -> int:
    """Analyze files named in argv and return a shell-compatible exit status."""
    parser = argparse.ArgumentParser(description="Analyze binary security properties")
    parser.add_argument("files", nargs="+", help="ELF or PE files to analyze")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--reference-libc", help="explicit ELF libc for fortify coverage")
    args = parser.parse_args(argv)

    # Retain successful analyses even if another requested file fails.
    results = []
    failed = False
    for path in args.files:
        try:
            results.append(analyze(path, args.reference_libc))
        except AnalysisError as exc:
            print(str(exc), file=sys.stderr)
            failed = True
    if args.json:
        output = [result.to_dict() for result in results]
        print(json.dumps(output[0] if len(args.files) == 1 and output else output, indent=2))
    else:
        for result in results:
            print(result.to_text())
    return int(failed)


def entrypoint() -> None:
    """Run the command-line interface and exit with its resulting status."""
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
