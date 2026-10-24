import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["SENTINEL_ROOT"] = str(ROOT)

import pytest  # noqa: E402


@pytest.fixture
def fixture_dir():
    return ROOT / "fixtures" / "vulnapp"
