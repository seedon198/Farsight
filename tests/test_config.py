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


def test_get_config_masscan_rate_default():
    assert get_config("masscan_rate") == 10000


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


def test_get_config_attack_surface_max_keywords_default():
    assert get_config("attack_surface_max_keywords") == 5


def test_get_api_endpoint_grayhatwarfare():
    assert (
        get_api_endpoint("grayhatwarfare")
        == "https://buckets.grayhatwarfare.com/api/v2"
    )


def test_get_api_endpoint_fullhunt():
    assert get_api_endpoint("fullhunt") == "https://fullhunt.io/api/v1"


def test_get_api_endpoint_netlas():
    assert get_api_endpoint("netlas") == "https://app.netlas.io/api"


def test_get_api_endpoint_zoomeye():
    assert get_api_endpoint("zoomeye") == "https://api.zoomeye.ai/v2"


def test_get_api_endpoint_onyphe():
    assert get_api_endpoint("onyphe") == "https://www.onyphe.io/api/v2"


def test_is_api_configured_true_when_grayhatwarfare_key_present(monkeypatch):
    monkeypatch.setitem(API_KEYS, "grayhatwarfare", "some-key")
    assert is_api_configured("grayhatwarfare") is True
