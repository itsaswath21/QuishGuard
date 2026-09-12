from urllib.parse import urlparse
import ipaddress


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


def analyze_url(url):
    risk_score = 0
    reasons = []

    https = check_https(url)
    ip_address = check_ip_address(url)
    suspicious_keywords = check_suspicious_keywords(url)

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

    if risk_score >= 50:
        verdict = "HIGH RISK"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "https": https,
        "ip_address": ip_address,
        "suspicious_keywords": suspicious_keywords,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons
    }


if __name__ == "__main__":
    test_url = "http://192.168.1.50/login"

    if is_url(test_url):
        print("This is a URL.")

        result = analyze_url(test_url)

        print("HTTPS:", "Yes" if result["https"] else "No")
        print("IP Address:", "Yes" if result["ip_address"] else "No")
        print(
            "Suspicious Keywords:",
            ", ".join(result["suspicious_keywords"])
            if result["suspicious_keywords"]
            else "None"
        )
        print("Risk Score:", result["risk_score"], "/ 100")
        print("Verdict:", result["verdict"])

        print("\nReasons:")
        for reason in result["reasons"]:
            print("-", reason)
    else:
        print("This is not a URL.")