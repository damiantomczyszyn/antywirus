"""Score fusion and verdict helpers."""

from .verdict import apply_to_file_verdict, apply_to_process_verdict, explain, fuse

__all__ = ["fuse", "apply_to_file_verdict", "apply_to_process_verdict", "explain"]
