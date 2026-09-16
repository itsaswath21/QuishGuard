import ipaddress
from urllib.parse import urlparse

import requests


MAX_REDIRECTS = 5


def is_public_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        ip = ipaddress.ip_address(hostname)

        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )

    except ValueError:
        return True


def analyze_redirects(url):
    if not is_public_url(url):
        return {
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "redirected": False,
            "error": "URL is not a public address"
        }

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            stream=True
        )

        redirect_chain = [item.url for item in response.history]
        redirect_chain.append(response.url)

        redirect_count = len(response.history)

        return {
            "redirect_count": redirect_count,
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "redirected": redirect_count > 0,
            "error": None
        }

    except requests.RequestException as error:
        return {
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "redirected": False,
            "error": str(error)
        }


if __name__ == "__main__":
    test_url = "https://example.com"

    result = analyze_redirects(test_url)

    print("Redirect Analysis")
    print("--------------------")

    print(
        "Redirected:",
        "Yes" if result["redirected"] else "No"
    )

    print(
        "Redirect Count:",
        result["redirect_count"]
    )

    print(
        "Final URL:",
        result["final_url"]
    )

    print()
    print("Redirect Chain:")

    for url in result["redirect_chain"]:
        print("->", url)

    if result["error"]:
        print()
        print("Error:", result["error"])