from urllib.parse import urlparse


def extract_domain(url):
    parsed = urlparse(url)

    return parsed.hostname


def extract_subdomain(url):
    domain = extract_domain(url)

    if not domain:
        return None

    parts = domain.split(".")

    if len(parts) > 2:
        return ".".join(parts[:-2])

    return None


def analyze_domain(url):
    domain = extract_domain(url)
    subdomain = extract_subdomain(url)

    return {
        "domain": domain,
        "subdomain": subdomain
    }


if __name__ == "__main__":
    test_url = "https://secure.example.com/login"

    result = analyze_domain(test_url)

    print("Domain Analysis")
    print("--------------------")
    print("Domain:", result["domain"])
    print(
        "Subdomain:",
        result["subdomain"] if result["subdomain"] else "None"
    )