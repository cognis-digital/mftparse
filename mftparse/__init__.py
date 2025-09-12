"""MFTPARSE — Analyze an NTFS $MFT CSV for timestomping and suspicious file activity."""
from mftparse.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
