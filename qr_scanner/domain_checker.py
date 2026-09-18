import tldextract
from urllib.parse import urlparse


def extract_domain(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return None

    extracted = tldextract.extract(parsed.hostname)

    if not extracted.domain or not extracted.suffix:
        return parsed.hostname

    return extracted.domain + "." + extracted.suffix


def extract_subdomain(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return None

    extracted = tldextract.extract(parsed.hostname)

    return extracted.subdomain if extracted.subdomain else None


def analyze_domain(url):
    domain = extract_domain(url)
    subdomain = extract_subdomain(url)

    return {
        "domain": domain,
        "subdomain": subdomain
    }


if __name__ == "__main__":
    test_url = "https://secure.example.co.uk/login"

    result = analyze_domain(test_url)

    print("Domain Analysis")
    print("--------------------")
    print("Domain:", result["domain"])
    print(
        "Subdomain:",
        result["subdomain"]
        if result["subdomain"]
        else "None"
    )