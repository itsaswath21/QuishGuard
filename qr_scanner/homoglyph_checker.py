from urllib.parse import urlparse


CONFUSABLE_CHARACTERS = {
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
    "Χ": "X",
}


def extract_domain(url):
    parsed = urlparse(url)

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


def analyze_homoglyphs(url):
    domain = extract_domain(url)

    confusable_characters = find_confusable_characters(domain)
    non_ascii = check_non_ascii(domain)

    return {
        "domain": domain,
        "non_ascii": non_ascii,
        "confusable_characters": confusable_characters,
        "suspicious": len(confusable_characters) > 0
    }


if __name__ == "__main__":
    test_url = "https://exаmple.com"

    result = analyze_homoglyphs(test_url)

    print("Homoglyph Analysis")
    print("--------------------")

    print("Domain:", result["domain"])

    print(
        "Non-ASCII Characters:",
        "Yes" if result["non_ascii"] else "No"
    )

    if result["confusable_characters"]:
        print("Confusable Characters:")

        for item in result["confusable_characters"]:
            print(
                "-",
                item["character"],
                "looks like",
                item["looks_like"]
            )
    else:
        print("Confusable Characters: None")

    print(
        "Suspicious:",
        "Yes" if result["suspicious"] else "No"
    )