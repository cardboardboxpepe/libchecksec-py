"""Inputs that a correctly typed installed package must reject."""

from libchecksec import analyze

analyze(42)
analyze("program").to_dict()["warnings"] = 42
