import time

import pytest


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry backoff must never make a test wait."""

    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
