from urllib.parse import urlparse

def is_url(text):
    parsed = urlparse(text)

    return parsed.scheme in ["http", "https"] and parsed.netloc != ""


test_url = "https://example.com"

if is_url(test_url):
    print("This is a URL.")
else:
    print("This is not a URL.")