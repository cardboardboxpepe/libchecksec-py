"""Exceptions raised by the library's analysis entry point."""

from pathlib import Path


class AnalysisError(Exception):
    """Represent an input or parsing failure during analysis."""


class ErrorParsingFailed(AnalysisError):
    """Report that the recognized binary at a path could not be parsed."""

    def __init__(self, path: Path, detail: str = "Unable to parse binary") -> None:
        """Store the failing path and an explanatory detail for the error."""
        self.path = path
        super().__init__(f"{detail}: {path}")


class UnsupportedFormatError(AnalysisError):
    """Report that the input path does not contain a supported file format."""

    def __init__(self, path: Path) -> None:
        """Store the path whose contents have an unsupported format."""
        self.path = path
        super().__init__(f"Unsupported binary format: {path}")
