"""Public API for reusable binary security analysis."""

from .api import analyze
from .errors import AnalysisError, ErrorParsingFailed, UnsupportedFormatError
from .models import (
    AddressInfo,
    AddressInfoDict,
    AddressLocation,
    AddressLocationDict,
    AnalysisResult,
    AnalysisResultDict,
    Finding,
    FindingDict,
    FortifyFinding,
    FortifyFindingDict,
    Status,
)

__all__ = [
    "AddressInfo",
    "AddressInfoDict",
    "AddressLocation",
    "AddressLocationDict",
    "AnalysisError",
    "AnalysisResult",
    "AnalysisResultDict",
    "ErrorParsingFailed",
    "Finding",
    "FindingDict",
    "FortifyFinding",
    "FortifyFindingDict",
    "Status",
    "UnsupportedFormatError",
    "analyze",
]
