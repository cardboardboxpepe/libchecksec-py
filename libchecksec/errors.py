"""Exceptions raised by the library's analysis entry point."""

from pathlib import Path


class AnalysisError(Exception):
    """Represent an input or parsing failure during analysis."""


class ErrorParsingFailed(AnalysisError):
    """Report that the recognized binary at a path could not be parsed."""

    def __init__(self, path: Path, detail: str = "Unable to parse binary") -> None:
        """Create a parsing error.

        Args:
            path: Path of the input that failed to parse.
            detail: Description of the failure included in the message.
        """
        self.path: Path = path
        super().__init__(f"{detail}: {path}")


class UnsupportedFormatError(AnalysisError):
    """Report that the input path does not contain a supported file format."""

    def __init__(self, path: Path) -> None:
        """Create an unsupported-format error.

        Args:
            path: Path of the input with an unsupported format.
        """
        self.path: Path = path
        super().__init__(f"Unsupported binary format: {path}")
