from urllib.parse import urlparse

def is_url(text):
    parsed = urlparse(text)

    return parsed.scheme in ["http", "https"] and parsed.netloc != ""


def check_https(url):
    parsed = urlparse(url)

    if parsed.scheme == "https":
        return True
    else:
        return False


test_url = "https://example.com"

if is_url(test_url):
    print("This is a URL.")

    if check_https(test_url):
        print("HTTPS: Secure connection")
    else:
        print("HTTPS: Not used")
else:
    print("This is not a URL.")