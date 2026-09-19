from urllib.parse import urlparse
import ipaddress

from domain_age_checker import get_domain_age
from homoglyph_checker import analyze_homoglyphs
from redirect_checker import analyze_redirects
from reputation_checker import check_reputation
from risk_engine import calculate_risk_score


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "password",
    "bank",
    "payment"
]


def is_url(text):
    parsed = urlparse(text)
    return parsed.scheme in ["http", "https"] and parsed.netloc != ""


def check_https(url):
    parsed = urlparse(url)
    return parsed.scheme == "https"


def check_ip_address(url):
    parsed = urlparse(url)

    try:
        ipaddress.ip_address(parsed.hostname)
        return True
    except (ValueError, TypeError):
        return False


def check_suspicious_keywords(url):
    url_lower = url.lower()
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            found_keywords.append(keyword)

    return found_keywords


def check_url_length(url):
    return len(url) > 75


def count_subdomains(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def check_hyphens(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    return hostname.count("-") >= 3


def check_at_symbol(url):
    parsed = urlparse(url)

    return "@" in parsed.netloc


def get_at_symbol_destination(url):
    parsed = urlparse(url)

    if "@" not in parsed.netloc:
        return None

    return parsed.hostname


def check_deceptive_at_symbol(url):
    parsed = urlparse(url)

    if "@" not in parsed.netloc:
        return False

    user_info = parsed.netloc.split("@")[0]
    hostname = parsed.hostname

    if not user_info or not hostname:
        return False

    return "." in user_info


def check_encoded_characters(url):
    return "%" in url


def analyze_domain_age(url):
    result = get_domain_age(url)

    if not result:
        return {
            "age_days": None,
            "age_years": None,
            "age_category": "Unavailable",
            "risk_points": 0
        }

    age_days = result["age_days"]

    if age_days < 30:
        risk_points = 30
    elif age_days < 180:
        risk_points = 20
    elif age_days < 365:
        risk_points = 10
    else:
        risk_points = 0

    return {
        "age_days": age_days,
        "age_years": result["age_years"],
        "age_category": result["age_category"],
        "risk_points": risk_points
    }


def analyze_url(url):
    https = check_https(url)
    ip_address = check_ip_address(url)
    suspicious_keywords = check_suspicious_keywords(url)
    url_length = check_url_length(url)
    subdomains = count_subdomains(url)
    many_hyphens = check_hyphens(url)

    at_symbol = check_at_symbol(url)
    at_symbol_destination = get_at_symbol_destination(url)
    deceptive_at_symbol = check_deceptive_at_symbol(url)

    encoded_characters = check_encoded_characters(url)

    domain_age = analyze_domain_age(url)
    homoglyph_analysis = analyze_homoglyphs(url)
    redirect_analysis = analyze_redirects(url)
    reputation_analysis = check_reputation(url)

    indicators = {
        "https": https,
        "ip_address": ip_address,
        "suspicious_keywords": suspicious_keywords,
        "url_length": url_length,
        "subdomains": subdomains,
        "many_hyphens": many_hyphens,
        "at_symbol": at_symbol,
        "at_symbol_destination": at_symbol_destination,
        "deceptive_at_symbol": deceptive_at_symbol,
        "encoded_characters": encoded_characters,
        "domain_age_days": domain_age["age_days"],
        "homoglyph_suspicious": homoglyph_analysis["suspicious"],
        "redirect_count": redirect_analysis["redirect_count"],
        "redirect_domain_changed": redirect_analysis["domain_changed"],
        "redirect_loop": redirect_analysis["redirect_loop"],
        "excessive_redirects": redirect_analysis["excessive_redirects"],
        "reputation_malicious": reputation_analysis["malicious"]
    }

    risk_result = calculate_risk_score(indicators)

    if redirect_analysis["redirect_count"] == 1:
        redirect_risk = 5
    elif redirect_analysis["redirect_count"] == 2:
        redirect_risk = 10
    elif redirect_analysis["redirect_count"] >= 3:
        redirect_risk = 20
    else:
        redirect_risk = 0

    reputation_risk = 50 if reputation_analysis["malicious"] else 0

    return {
        "https": https,
        "ip_address": ip_address,
        "suspicious_keywords": suspicious_keywords,
        "url_length": url_length,
        "subdomains": subdomains,
        "many_hyphens": many_hyphens,
        "at_symbol": at_symbol,
        "at_symbol_destination": at_symbol_destination,
        "deceptive_at_symbol": deceptive_at_symbol,
        "encoded_characters": encoded_characters,

        "domain_age_days": domain_age["age_days"],
        "domain_age_years": domain_age["age_years"],
        "domain_age_category": domain_age["age_category"],
        "domain_age_risk": domain_age["risk_points"],

        "homoglyph_suspicious": homoglyph_analysis["suspicious"],
        "homoglyph_non_ascii": homoglyph_analysis["non_ascii"],
        "homoglyph_characters": homoglyph_analysis["confusable_characters"],
        "homoglyph_normalized_domain": homoglyph_analysis["normalized_domain"],

        "redirect_count": redirect_analysis["redirect_count"],
        "redirect_risk": redirect_risk,
        "redirect_domain_changed": redirect_analysis["domain_changed"],
        "redirect_loop": redirect_analysis["redirect_loop"],
        "excessive_redirects": redirect_analysis["excessive_redirects"],
        "final_url": redirect_analysis["final_url"],
        "redirect_chain": redirect_analysis["redirect_chain"],

        "reputation_checked": reputation_analysis["checked"],
        "reputation_malicious": reputation_analysis["malicious"],
        "reputation_threats": reputation_analysis["threats"],
        "reputation_error": reputation_analysis["error"],
        "reputation_risk": reputation_risk,

        "risk_score": risk_result["risk_score"],
        "verdict": risk_result["verdict"],
        "reasons": risk_result["reasons"]
    }


if __name__ == "__main__":
    test_url = "https://example.com"

    if is_url(test_url):
        result = analyze_url(test_url)

        print("URL Analysis")
        print("--------------------")

        print("URL:", test_url)

        print(
            "HTTPS:",
            "Yes" if result["https"] else "No"
        )

        print(
            "IP Address:",
            "Yes" if result["ip_address"] else "No"
        )

        print(
            "Suspicious Keywords:",
            ", ".join(result["suspicious_keywords"])
            if result["suspicious_keywords"]
            else "None"
        )

        print(
            "Long URL:",
            "Yes" if result["url_length"] else "No"
        )

        print(
            "Subdomains:",
            result["subdomains"]
        )

        print(
            "Many Hyphens:",
            "Yes" if result["many_hyphens"] else "No"
        )

        print(
            "@ Symbol:",
            "Yes" if result["at_symbol"] else "No"
        )

        print(
            "@ Destination:",
            result["at_symbol_destination"]
            if result["at_symbol_destination"]
            else "None"
        )

        print(
            "Deceptive @ Pattern:",
            "Yes" if result["deceptive_at_symbol"] else "No"
        )

        print(
            "Encoded Characters:",
            "Yes" if result["encoded_characters"]
            else "No"
        )

        print(
            "Domain Age:",
            str(result["domain_age_years"]) + " years"
            if result["domain_age_years"] is not None
            else "Unavailable"
        )

        print(
            "Domain Age Category:",
            result["domain_age_category"]
        )

        print(
            "Homoglyph Detection:",
            "Suspicious"
            if result["homoglyph_suspicious"]
            else "Normal"
        )

        print(
            "Non-ASCII Domain:",
            "Yes" if result["homoglyph_non_ascii"]
            else "No"
        )

        print(
            "Normalized Domain:",
            result["homoglyph_normalized_domain"]
            if result["homoglyph_normalized_domain"]
            else "Unavailable"
        )

        print()
        print("Redirect Analysis")
        print("--------------------")

        print(
            "Redirect Count:",
            result["redirect_count"]
        )

        print(
            "Domain Changed:",
            "Yes" if result["redirect_domain_changed"]
            else "No"
        )

        print(
            "Redirect Loop:",
            "Yes" if result["redirect_loop"]
            else "No"
        )

        print(
            "Excessive Redirects:",
            "Yes" if result["excessive_redirects"]
            else "No"
        )

        print(
            "Final URL:",
            result["final_url"]
        )

        print()
        print("Risk Score:", result["risk_score"], "/ 100")
        print("Verdict:", result["verdict"])

        print()
        print("Reasons")
        print("--------------------")

        if result["reasons"]:
            for reason in result["reasons"]:
                print("-", reason)
        else:
            print("- No suspicious indicators detected.")

    else:
        print("This is not a URL.")