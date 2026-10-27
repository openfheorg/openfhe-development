"""Ensure `reference/` is importable as the package root for `import ci_ckks`."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
