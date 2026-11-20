"""Shared paths for real ELF and PE regression fixtures."""

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def binaries() -> Path:
    """Return the initialized pinned fixture directory; fail if it is missing."""
    directory = Path(__file__).parent / "binaries"
    if not (directory / "elf" / "default").is_file():
        pytest.fail("Initialize fixtures with git submodule update --init tests/binaries")
    return directory
