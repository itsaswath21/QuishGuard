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

        try:
            ip = ipaddress.ip_address(hostname)

            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )

        except ValueError:
            return True

    except ValueError:
        return False


def get_hostname(url):
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except ValueError:
        return None


def analyze_redirects(url):
    if not is_public_url(url):
        return {
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "redirected": False,
            "domain_changed": False,
            "redirect_loop": False,
            "excessive_redirects": False,
            "error": "URL is not a public address"
        }

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        response = session.get(
            url,
            allow_redirects=True,
            timeout=5,
            stream=True
        )

        redirect_chain = [url]

        for item in response.history:
            redirect_chain.append(item.url)

        if response.url not in redirect_chain:
            redirect_chain.append(response.url)

        redirect_count = len(response.history)

        original_hostname = get_hostname(url)
        final_hostname = get_hostname(response.url)

        domain_changed = (
            original_hostname is not None
            and final_hostname is not None
            and original_hostname.lower() != final_hostname.lower()
        )

        redirect_loop = (
            len(set(redirect_chain)) != len(redirect_chain)
        )

        excessive_redirects = redirect_count >= MAX_REDIRECTS

        return {
            "redirect_count": redirect_count,
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "redirected": redirect_count > 0,
            "domain_changed": domain_changed,
            "redirect_loop": redirect_loop,
            "excessive_redirects": excessive_redirects,
            "error": None
        }

    except requests.TooManyRedirects:
        return {
            "redirect_count": MAX_REDIRECTS,
            "final_url": url,
            "redirect_chain": [url],
            "redirected": True,
            "domain_changed": False,
            "redirect_loop": True,
            "excessive_redirects": True,
            "error": "Maximum redirect limit exceeded"
        }

    except requests.RequestException as error:
        return {
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "redirected": False,
            "domain_changed": False,
            "redirect_loop": False,
            "excessive_redirects": False,
            "error": str(error)
        }

    finally:
        session.close()


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
        "Domain Changed:",
        "Yes" if result["domain_changed"] else "No"
    )

    print(
        "Redirect Loop:",
        "Yes" if result["redirect_loop"] else "No"
    )

    print(
        "Excessive Redirects:",
        "Yes" if result["excessive_redirects"] else "No"
    )

    print(
        "Final URL:",
        result["final_url"]
    )

    print()
    print("Redirect Chain:")

    for redirect_url in result["redirect_chain"]:
        print("->", redirect_url)

    if result["error"]:
        print()
        print("Error:", result["error"])