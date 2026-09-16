from datetime import datetime, timezone
from urllib.parse import urlparse
import whoisdomain


def get_domain(url):
    parsed = urlparse(url)
    return parsed.hostname


def get_domain_age(url):
    domain = get_domain(url)

    if not domain:
        return None

    try:
        result = whoisdomain.query(domain)
        creation_date = result.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        if creation_date.tzinfo is not None:
            current_time = datetime.now(timezone.utc)
            creation_date = creation_date.astimezone(timezone.utc)
        else:
            current_time = datetime.now()

        age_days = (current_time - creation_date).days
        age_years = round(age_days / 365, 2)

        return {
            "creation_date": creation_date,
            "age_days": age_days,
            "age_years": age_years
        }

    except Exception as error:
        print("Domain lookup failed:", error)
        return None


if __name__ == "__main__":
    test_url = "https://google.com"

    result = get_domain_age(test_url)

    print("Domain Age Analysis")
    print("--------------------")

    if result:
        print("Creation Date:", result["creation_date"])
        print("Domain Age:", result["age_years"], "years")
        print("Domain Age:", result["age_days"], "days")
    else:
        print("Could not retrieve domain age.")