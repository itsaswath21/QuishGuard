import ipaddress
from urllib.parse import urljoin, urlparse

import requests


MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 5

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308
}


def is_public_hostname(hostname):
    if not hostname:
        return False

    hostname = hostname.lower().strip(".")

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


def is_public_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.hostname:
            return False

        return is_public_hostname(parsed.hostname)

    except ValueError:
        return False


def get_hostname(url):
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except ValueError:
        return None


def get_base_domain(hostname):
    if not hostname:
        return None

    hostname = hostname.lower().strip(".")

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


def is_same_base_domain(original_url, final_url):
    original_hostname = get_hostname(original_url)
    final_hostname = get_hostname(final_url)

    original_domain = get_base_domain(original_hostname)
    final_domain = get_base_domain(final_hostname)

    if not original_domain or not final_domain:
        return False

    return original_domain == final_domain


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

    redirect_chain = [url]
    current_url = url

    try:

        for redirect_number in range(MAX_REDIRECTS + 1):

            if not is_public_url(current_url):

                return {
                    "redirect_count": redirect_number,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirected": redirect_number > 0,
                    "domain_changed": not is_same_base_domain(
                        url,
                        current_url
                    ),
                    "redirect_loop": current_url in redirect_chain[:-1],
                    "excessive_redirects": False,
                    "error": "Redirect target is not a public address"
                }

            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                stream=True
            )

            status_code = response.status_code

            if status_code not in REDIRECT_STATUS_CODES:

                domain_changed = (
                    len(redirect_chain) > 1
                    and not is_same_base_domain(
                        url,
                        current_url
                    )
                )

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirected": len(redirect_chain) > 1,
                    "domain_changed": domain_changed,
                    "redirect_loop": False,
                    "excessive_redirects": False,
                    "error": None
                }

            location = response.headers.get("Location")

            if not location:

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirected": len(redirect_chain) > 1,
                    "domain_changed": False,
                    "redirect_loop": False,
                    "excessive_redirects": False,
                    "error": "Redirect response has no Location header"
                }

            next_url = urljoin(
                current_url,
                location
            )

            if next_url in redirect_chain:

                redirect_chain.append(next_url)

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "final_url": next_url,
                    "redirect_chain": redirect_chain,
                    "redirected": True,
                    "domain_changed": not is_same_base_domain(
                        url,
                        next_url
                    ),
                    "redirect_loop": True,
                    "excessive_redirects": False,
                    "error": "Redirect loop detected"
                }

            if not is_public_url(next_url):

                redirect_chain.append(next_url)

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "final_url": next_url,
                    "redirect_chain": redirect_chain,
                    "redirected": True,
                    "domain_changed": not is_same_base_domain(
                        url,
                        next_url
                    ),
                    "redirect_loop": False,
                    "excessive_redirects": False,
                    "error": "Redirect target is not a public address"
                }

            redirect_chain.append(next_url)

            current_url = next_url

        return {
            "redirect_count": MAX_REDIRECTS,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "redirected": True,
            "domain_changed": not is_same_base_domain(
                url,
                current_url
            ),
            "redirect_loop": False,
            "excessive_redirects": True,
            "error": "Maximum redirect limit exceeded"
        }

    except requests.RequestException as error:

        return {
            "redirect_count": len(redirect_chain) - 1,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "redirected": len(redirect_chain) > 1,
            "domain_changed": not is_same_base_domain(
                url,
                current_url
            ),
            "redirect_loop": False,
            "excessive_redirects": False,
            "error": str(error)
        }

    finally:
        session.close()


if __name__ == "__main__":

    test_url = "https://google.com"

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