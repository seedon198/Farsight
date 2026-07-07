"""Tests for farsight.config."""

from farsight.config import (
    get_config,
    get_api_key,
    get_api_endpoint,
    is_api_configured,
    get_available_apis,
    API_KEYS,
)


def test_get_config_returns_default_value():
    assert get_config("timeout") == 30


def test_get_config_missing_key_returns_provided_default():
    assert get_config("does_not_exist", "fallback") == "fallback"


def test_get_config_missing_key_no_default_returns_none():
    assert get_config("does_not_exist") is None


def test_get_api_key_unknown_provider_returns_none():
    assert get_api_key("not_a_real_provider") is None


def test_get_api_endpoint_known_provider():
    assert get_api_endpoint("shodan") == "https://api.shodan.io"


def test_get_api_endpoint_unknown_provider_returns_none():
    assert get_api_endpoint("not_a_real_provider") is None


def test_is_api_configured_false_when_no_key(monkeypatch):
    monkeypatch.setitem(API_KEYS, "shodan", None)
    assert is_api_configured("shodan") is False


def test_is_api_configured_true_when_key_present(monkeypatch):
    monkeypatch.setitem(API_KEYS, "shodan", "some-key")
    assert is_api_configured("shodan") is True


def test_get_available_apis_covers_all_providers():
    apis = get_available_apis()
    assert set(apis.keys()) == set(API_KEYS.keys())
    assert all(isinstance(v, bool) for v in apis.values())
