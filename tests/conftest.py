"""
Pytest global fixtures.
"""

from pathlib import Path
import pytest

@pytest.fixture
def modules_dir():
    return Path(__file__).resolve().parent.parent / "modules"
