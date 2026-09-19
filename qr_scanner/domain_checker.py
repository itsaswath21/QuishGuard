import tldextract
from urllib.parse import urlparse


def get_hostname(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return None

    return parsed.hostname


def extract_domain(url):
    hostname = get_hostname(url)

    if not hostname:
        return None

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return hostname

    return extracted.domain + "." + extracted.suffix


def extract_subdomain(url):
    hostname = get_hostname(url)

    if not hostname:
        return None

    extracted = tldextract.extract(hostname)

    return extracted.subdomain if extracted.subdomain else None


def count_subdomains(url):
    subdomain = extract_subdomain(url)

    if not subdomain:
        return 0

    return len(subdomain.split("."))


def check_many_subdomains(url):
    return count_subdomains(url) >= 3


def check_many_hyphens(url):
    hostname = get_hostname(url)

    if not hostname:
        return False

    return hostname.count("-") >= 3


def analyze_domain(url):
    hostname = get_hostname(url)
    domain = extract_domain(url)
    subdomain = extract_subdomain(url)
    subdomain_count = count_subdomains(url)

    return {
        "hostname": hostname,
        "domain": domain,
        "subdomain": subdomain,
        "subdomain_count": subdomain_count,
        "many_subdomains": subdomain_count >= 3,
        "many_hyphens": check_many_hyphens(url)
    }


if __name__ == "__main__":
    test_url = "https://secure.login.example.co.uk/login"

    result = analyze_domain(test_url)

    print("Domain Analysis")
    print("--------------------")

    print(
        "Hostname:",
        result["hostname"]
        if result["hostname"]
        else "None"
    )

    print(
        "Domain:",
        result["domain"]
        if result["domain"]
        else "None"
    )

    print(
        "Subdomain:",
        result["subdomain"]
        if result["subdomain"]
        else "None"
    )

    print(
        "Subdomain Count:",
        result["subdomain_count"]
    )

    print(
        "Many Subdomains:",
        "Yes" if result["many_subdomains"] else "No"
    )

    print(
        "Many Hyphens:",
        "Yes" if result["many_hyphens"] else "No"
    )