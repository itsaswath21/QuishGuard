import sys
import os

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "qr_scanner")
    )
)

from url_checker import (
    is_url,
    check_https,
    check_ip_address,
    check_suspicious_keywords,
    check_url_length,
    count_subdomains,
    check_hyphens,
    check_at_symbol,
    get_at_symbol_destination,
    check_deceptive_at_symbol,
    check_encoded_characters,
)


def test_valid_url():
    assert is_url("https://example.com")


def test_invalid_url():
    assert not is_url("hello world")


def test_https_detection():
    assert check_https("https://example.com")
    assert not check_https("http://example.com")


def test_ip_address_detection():
    assert check_ip_address("http://192.168.1.50/login")
    assert not check_ip_address("https://example.com")


def test_suspicious_keywords():
    result = check_suspicious_keywords(
        "https://example.com/login"
    )

    assert "login" in result


def test_url_length():
    long_url = (
        "https://example.com/"
        + "a" * 80
    )

    assert check_url_length(long_url)


def test_subdomain_detection():
    assert count_subdomains(
        "https://one.two.example.com"
    ) == 2


def test_hyphen_detection():
    assert check_hyphens(
        "https://pay-secure-account-login.com"
    )


def test_at_symbol_detection():
    assert check_at_symbol(
        "https://example.com@google.com"
    )


def test_at_symbol_destination():
    assert get_at_symbol_destination(
        "https://example.com@google.com"
    ) == "google.com"


def test_deceptive_at_symbol():
    assert check_deceptive_at_symbol(
        "https://example.com@google.com"
    )


def test_normal_at_symbol_pattern():
    assert not check_deceptive_at_symbol(
        "https://user@example.com"
    )


def test_encoded_character_detection():
    assert check_encoded_characters(
        "https://example.com/%6C%6F%67%69%6E"
    )


def test_clean_url_has_no_at_symbol():
    assert not check_at_symbol(
        "https://example.com"
    )


print("All QuishGuard URL detection tests loaded successfully.")