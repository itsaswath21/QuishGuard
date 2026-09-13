from urllib.parse import urlparse
import ipaddress

from domain_age_checker import get_domain_age


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
    except ValueError:
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
    return "@" in url


def check_encoded_characters(url):
    return "%" in url


def analyze_domain_age(url):
    result = get_domain_age(url)

    if not result:
        return {
            "age_days": None,
            "age_years": None,
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
        "risk_points": risk_points
    }


def analyze_url(url):
    risk_score = 0
    reasons = []

    https = check_https(url)
    ip_address = check_ip_address(url)
    suspicious_keywords = check_suspicious_keywords(url)
    url_length = check_url_length(url)
    subdomains = count_subdomains(url)
    many_hyphens = check_hyphens(url)
    at_symbol = check_at_symbol(url)
    encoded_characters = check_encoded_characters(url)

    domain_age = analyze_domain_age(url)

    if not https:
        risk_score += 20
        reasons.append("URL does not use HTTPS")

    if ip_address:
        risk_score += 30
        reasons.append("URL uses an IP address instead of a domain")

    if suspicious_keywords:
        risk_score += 10
        reasons.append(
            "Suspicious keyword detected: "
            + ", ".join(suspicious_keywords)
        )

    if url_length:
        risk_score += 10
        reasons.append("URL is unusually long")

    if subdomains >= 3:
        risk_score += 10
        reasons.append("URL contains many subdomains")

    if many_hyphens:
        risk_score += 5
        reasons.append("Domain contains many hyphens")

    if at_symbol:
        risk_score += 20
        reasons.append("URL contains an @ symbol")

    if encoded_characters:
        risk_score += 5
        reasons.append("URL contains encoded characters")

    if domain_age["risk_points"] > 0:
        risk_score += domain_age["risk_points"]

        if domain_age["age_days"] < 30:
            reasons.append("Domain was registered less than 30 days ago")
        elif domain_age["age_days"] < 180:
            reasons.append("Domain was registered less than 6 months ago")
        else:
            reasons.append("Domain was registered less than 1 year ago")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "https": https,
        "ip_address": ip_address,
        "suspicious_keywords": suspicious_keywords,
        "url_length": url_length,
        "subdomains": subdomains,
        "many_hyphens": many_hyphens,
        "at_symbol": at_symbol,
        "encoded_characters": encoded_characters,
        "domain_age_days": domain_age["age_days"],
        "domain_age_years": domain_age["age_years"],
        "domain_age_risk": domain_age["risk_points"],
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons
    }


if __name__ == "__main__":
    test_url = "https://example.com"

    if is_url(test_url):
        result = analyze_url(test_url)

        print("URL Analysis")
        print("--------------------")
        print("HTTPS:", "Yes" if result["https"] else "No")
        print("IP Address:", "Yes" if result["ip_address"] else "No")

        print(
            "Suspicious Keywords:",
            ", ".join(result["suspicious_keywords"])
            if result["suspicious_keywords"]
            else "None"
        )

        print("Long URL:", "Yes" if result["url_length"] else "No")
        print("Subdomains:", result["subdomains"])

        print(
            "Many Hyphens:",
            "Yes" if result["many_hyphens"] else "No"
        )

        print(
            "@ Symbol:",
            "Yes" if result["at_symbol"] else "No"
        )

        print(
            "Encoded Characters:",
            "Yes" if result["encoded_characters"] else "No"
        )

        print(
            "Domain Age:",
            result["domain_age_years"],
            "years"
            if result["domain_age_years"] is not None
            else "Unavailable"
        )

        print(
            "Domain Age Risk:",
            "+" + str(result["domain_age_risk"])
        )

        print()
        print("Risk Score:", result["risk_score"], "/ 100")
        print("Verdict:", result["verdict"])

        print()
        print("Reasons:")

        for reason in result["reasons"]:
            print("-", reason)
    else:
        print("This is not a URL.")