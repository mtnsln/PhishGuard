import pytest

from phishguard.analyzer import analyze_url


def codes(url):
    return {item["code"] for item in analyze_url(url)["findings"]}


def test_plain_domain_is_normalised():
    report = analyze_url("example.com")
    assert report["normalised_url"] == "https://example.com"
    assert report["risk_level"] == "low"
    assert report["analysis_type"] == "local_heuristics"


def test_http_warning():
    assert "no_https" in codes("http://example.com")


def test_ip_host_warning():
    assert "ip_host" in codes("http://192.0.2.10/login")


def test_at_symbol_warning():
    assert "at_symbol" in codes("https://trusted.example@evil.example/login")


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        analyze_url("  ")


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "ftp://example.com",
    "https://example..com",
    "https://-bad-.com",
    "https://example.com\\@evil.com",
    "https://example.com path",
    "https://example%2ecom",
    "https://example.com:99999",
])
def test_invalid_or_unsupported_urls_rejected(url):
    with pytest.raises(ValueError):
        analyze_url(url)


def test_score_is_bounded():
    report = analyze_url("http://192.0.2.5/verify/login/account/" + "x" * 150)
    assert 0 <= report["risk_score"] <= 100


def test_url_length_limit():
    with pytest.raises(ValueError):
        analyze_url("https://example.com/" + "a" * 2050)


def test_punycode_is_flagged():
    assert "punycode" in codes("https://xn--ypal-43d9g.com")


def test_brand_in_unrelated_subdomain_is_detected():
    assert "brand_in_subdomain" in codes("https://paypal.com.example.org/login")


def test_google_brand_in_unrelated_subdomain_is_detected():
    assert "brand_in_subdomain" in codes("https://google.com.fake-domain.test")


def test_real_paypal_domain_not_flagged_as_impersonation():
    assert not ({"brand_in_subdomain", "brand_in_domain", "brand_lookalike"} & codes("https://paypal.com"))


def test_real_google_subdomain_not_flagged_as_impersonation():
    assert not ({"brand_in_subdomain", "brand_in_domain", "brand_lookalike"} & codes("https://accounts.google.com"))


def test_brand_in_subdomain_with_extra_text():
    assert "brand_in_subdomain" in codes("https://paypal-login.example.org")


def test_brand_in_registered_domain_with_extra_text():
    assert "brand_in_domain" in codes("https://paypal-login.com")


def test_typo_in_registered_domain():
    assert "brand_lookalike" in codes("https://paypa1.com")


def test_brand_in_path_alone_is_not_domain_impersonation():
    assert not ({"brand_in_subdomain", "brand_in_domain", "brand_lookalike"} & codes("https://example.org/paypal/login"))


@pytest.mark.parametrize("url", [
    "https://paypal.co.uk",
    "https://amazon.co.uk",
    "https://paypal.com.az",
    "https://www.google.com",
])
def test_known_legitimate_domain_patterns_are_not_brand_flagged(url):
    assert not ({"brand_in_subdomain", "brand_in_domain", "brand_lookalike"} & codes(url))


def test_registrable_domain_is_returned_as_estimate():
    report = analyze_url("https://accounts.google.com")
    assert report["registrable_domain_estimate"] == "google.com"


def test_many_subdomains_are_reported():
    assert "many_subdomains" in codes("https://a.b.c.example.com")
