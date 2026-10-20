from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.corpus import build_corpus


@pytest.fixture
def corpus(tmp_path: Path) -> dict[str, Path]:
    return build_corpus(tmp_path / "corpus")
