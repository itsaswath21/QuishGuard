RISK_WEIGHTS = {
    "no_https": 20,
    "ip_address": 30,
    "suspicious_keywords": 10,
    "long_url": 10,
    "many_subdomains": 10,
    "many_hyphens": 5,
    "at_symbol": 20,
    "deceptive_at_symbol": 15,
    "encoded_characters": 5,
    "domain_age_30_days": 30,
    "domain_age_180_days": 20,
    "domain_age_365_days": 10,
    "homoglyph": 25,
    "redirect_1": 5,
    "redirect_2": 10,
    "redirect_3_or_more": 20,
    "redirect_domain_change": 10,
    "redirect_loop": 20,
    "excessive_redirects": 15,
    "malicious_reputation": 50
}


def calculate_risk_score(indicators):
    score = 0
    reasons = []

    if not indicators["https"]:
        score += RISK_WEIGHTS["no_https"]
        reasons.append("URL does not use HTTPS")

    if indicators["ip_address"]:
        score += RISK_WEIGHTS["ip_address"]
        reasons.append("URL uses an IP address instead of a domain")

    if indicators["suspicious_keywords"]:
        score += RISK_WEIGHTS["suspicious_keywords"]
        reasons.append(
            "Suspicious keyword detected: "
            + ", ".join(indicators["suspicious_keywords"])
        )

    if indicators["url_length"]:
        score += RISK_WEIGHTS["long_url"]
        reasons.append("URL is unusually long")

    if indicators["subdomains"] >= 3:
        score += RISK_WEIGHTS["many_subdomains"]
        reasons.append("URL contains many subdomains")

    if indicators["many_hyphens"]:
        score += RISK_WEIGHTS["many_hyphens"]
        reasons.append("Domain contains many hyphens")

    if indicators["at_symbol"]:
        score += RISK_WEIGHTS["at_symbol"]

        if indicators["at_symbol_destination"]:
            reasons.append(
                "URL contains an @ symbol and the actual destination is "
                + indicators["at_symbol_destination"]
            )
        else:
            reasons.append("URL contains an @ symbol")

    if indicators["deceptive_at_symbol"]:
        score += RISK_WEIGHTS["deceptive_at_symbol"]
        reasons.append(
            "Possible deceptive URL: domain-like text appears before the @ symbol"
        )

    if indicators["encoded_characters"]:
        score += RISK_WEIGHTS["encoded_characters"]
        reasons.append("URL contains encoded characters")

    domain_age_days = indicators["domain_age_days"]

    if domain_age_days is not None:
        if domain_age_days < 30:
            score += RISK_WEIGHTS["domain_age_30_days"]
            reasons.append(
                "Domain was registered less than 30 days ago"
            )
        elif domain_age_days < 180:
            score += RISK_WEIGHTS["domain_age_180_days"]
            reasons.append(
                "Domain was registered less than 6 months ago"
            )
        elif domain_age_days < 365:
            score += RISK_WEIGHTS["domain_age_365_days"]
            reasons.append(
                "Domain was registered less than 1 year ago"
            )

    if indicators["homoglyph_suspicious"]:
        score += RISK_WEIGHTS["homoglyph"]
        reasons.append(
            "Domain contains look-alike Unicode characters"
        )

    redirect_count = indicators["redirect_count"]

    if redirect_count == 1:
        score += RISK_WEIGHTS["redirect_1"]
    elif redirect_count == 2:
        score += RISK_WEIGHTS["redirect_2"]
    elif redirect_count >= 3:
        score += RISK_WEIGHTS["redirect_3_or_more"]

    if redirect_count > 0:
        reasons.append(
            "URL redirects through "
            + str(redirect_count)
            + " intermediate URL(s)"
        )

    if indicators["redirect_domain_changed"]:
        score += RISK_WEIGHTS["redirect_domain_change"]
        reasons.append(
            "Redirect changes the destination domain"
        )

    if indicators["redirect_loop"]:
        score += RISK_WEIGHTS["redirect_loop"]
        reasons.append(
            "Redirect chain contains a possible loop"
        )

    if indicators["excessive_redirects"]:
        score += RISK_WEIGHTS["excessive_redirects"]
        reasons.append(
            "URL uses an excessive number of redirects"
        )

    if indicators["reputation_malicious"]:
        score += RISK_WEIGHTS["malicious_reputation"]
        reasons.append(
            "URL is flagged by VirusTotal as malicious"
        )

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons
    }


if __name__ == "__main__":
    test_indicators = {
        "https": True,
        "ip_address": False,
        "suspicious_keywords": [],
        "url_length": False,
        "subdomains": 0,
        "many_hyphens": False,
        "at_symbol": False,
        "at_symbol_destination": None,
        "deceptive_at_symbol": False,
        "encoded_characters": False,
        "domain_age_days": None,
        "homoglyph_suspicious": False,
        "redirect_count": 2,
        "redirect_domain_changed": True,
        "redirect_loop": False,
        "excessive_redirects": False,
        "reputation_malicious": False
    }

    result = calculate_risk_score(test_indicators)

    print("Risk Engine Test")
    print("--------------------")
    print("Risk Score:", result["risk_score"], "/ 100")
    print("Verdict:", result["verdict"])
    print()
    print("Reasons:")

    for reason in result["reasons"]:
        print("-", reason)