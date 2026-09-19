from urllib.parse import urlparse


CONFUSABLE_CHARACTERS = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ɡ": "g",

    # Greek
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X"
}


def extract_domain(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return None

    return parsed.hostname


def find_confusable_characters(domain):
    if not domain:
        return []

    found = []

    for character in domain:
        if character in CONFUSABLE_CHARACTERS:
            found.append({
                "character": character,
                "looks_like": CONFUSABLE_CHARACTERS[character]
            })

    return found


def check_non_ascii(domain):
    if not domain:
        return False

    return any(ord(character) > 127 for character in domain)


def normalize_domain(domain):
    if not domain:
        return None

    normalized = ""

    for character in domain:
        if character in CONFUSABLE_CHARACTERS:
            normalized += CONFUSABLE_CHARACTERS[character]
        else:
            normalized += character

    return normalized


def analyze_homoglyphs(url):
    domain = extract_domain(url)

    if not domain:
        return {
            "domain": None,
            "non_ascii": False,
            "confusable_characters": [],
            "normalized_domain": None,
            "suspicious": False
        }

    confusable_characters = find_confusable_characters(domain)
    non_ascii = check_non_ascii(domain)
    normalized_domain = normalize_domain(domain)

    suspicious = len(confusable_characters) > 0

    return {
        "domain": domain,
        "non_ascii": non_ascii,
        "confusable_characters": confusable_characters,
        "normalized_domain": normalized_domain,
        "suspicious": suspicious
    }


if __name__ == "__main__":
    test_url = "https://exаmple.com"

    result = analyze_homoglyphs(test_url)

    print("Homoglyph Analysis")
    print("--------------------")

    print("Domain:", result["domain"])
    print("Non-ASCII:", result["non_ascii"])
    print("Suspicious:", result["suspicious"])
    print("Normalized Domain:", result["normalized_domain"])

    print()
    print("Confusable Characters:")

    if result["confusable_characters"]:
        for item in result["confusable_characters"]:
            print(
                "-",
                item["character"],
                "looks like",
                item["looks_like"]
            )
    else:
        print("- None")