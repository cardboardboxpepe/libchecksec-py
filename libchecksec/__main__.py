"""Minimal command-line interface for explicit binary analysis."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import AnalysisError, AnalysisResult, analyze


class _Arguments(argparse.Namespace):
    """Hold the parsed command-line options with their concrete types."""

    def __init__(self) -> None:
        """Initialize defaults before argparse populates the namespace."""
        super().__init__()
        self.files: list[str] = []
        self.json: bool = False
        self.reference_libc: str | None = None


def main(argv: Sequence[str] | None = None) -> int:
    """Analyze files named in command-line arguments.

    Args:
        argv: Arguments excluding the program name, or None to use sys.argv.

    Returns:
        Zero if all analyses succeed, otherwise one.

    Raises:
        SystemExit: Argument parsing fails or displays help.
    """
    parser = argparse.ArgumentParser(description="Analyze binary security properties")
    _ = parser.add_argument("files", nargs="+", help="ELF or PE files to analyze")
    _ = parser.add_argument("--json", action="store_true", help="output JSON")
    _ = parser.add_argument("--reference-libc", help="explicit ELF libc for fortify coverage")
    args = parser.parse_args(argv, namespace=_Arguments())

    # Retain successful analyses even if another requested file fails.
    results: list[AnalysisResult] = []
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
