"""Helpers for values returned by LIEF."""


def lief_text(value: str | bytes) -> str:
    """Return a LIEF name as text, preserving undecodable bytes as escapes."""
    return value.decode("utf-8", errors="backslashreplace") if isinstance(value, bytes) else value
