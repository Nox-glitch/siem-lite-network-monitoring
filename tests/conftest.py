
import pytest


@pytest.fixture(autouse=True)
def clear_enrichment_cache():
    from ingestion.enrichment import _cache
    _cache.clear()
    yield
    _cache.clear()
