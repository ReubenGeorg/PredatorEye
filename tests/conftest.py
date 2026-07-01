"""
tests/conftest.py
==================
Project-root path setup and shared fixtures.

pytest does not add the project root to sys.path automatically when there
is no setup.py / pyproject.toml.  Inserting it here (in the root conftest)
makes every import in the test suite work without needing an install step.
"""

import sys
import os

# Insert project root so `from protection import ...` works from the test runner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
