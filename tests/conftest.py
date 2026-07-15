import pytest

from farsight import config


@pytest.fixture(autouse=True)
def isolated_intelx_cache(tmp_path, monkeypatch):
    """Redirect the IntelX search cache to a per-test temp dir.

    Without this, cache entries written by one test (keyed by a hash of
    the search endpoint + params) would be read back by any later test
    using the same domain/params, making tests order-dependent.
    """
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
