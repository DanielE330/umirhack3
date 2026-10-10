import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honeymind.analyzer import Analyzer  # noqa: E402
from honeymind.corpus import build  # noqa: E402
from honeymind.model import ThreatModel  # noqa: E402


@pytest.fixture(scope="session")
def model() -> ThreatModel:
    s = build()
    return ThreatModel.train([x.text for x in s], [x.label for x in s])


@pytest.fixture(scope="session")
def analyzer(model) -> Analyzer:
    return Analyzer(model)


@pytest.fixture(scope="session")
def rules_only() -> Analyzer:
    return Analyzer(None)
