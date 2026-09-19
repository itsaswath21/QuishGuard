
import os
import base64

import requests
from dotenv import load_dotenv


load_dotenv()


VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/"


def create_url_id(url):
    """
    Create the VirusTotal URL identifier.

    VirusTotal accepts an unpadded URL-safe Base64
    representation as a URL identifier.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def check_reputation(url):

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "checked": False,
            "malicious": False,
            "threats": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": api_key
    }

    try:

        url_id = create_url_id(url)

        report_url = (
            VIRUSTOTAL_URL_REPORT
            + url_id
        )

        response = requests.get(
            report_url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:

            return {
                "checked": False,
                "malicious": False,
                "threats": [],
                "malicious_count": 0,
                "suspicious_count": 0,
                "error": "VirusTotal has no existing report for this URL"
            }

        if response.status_code != 200:

            return {
                "checked": False,
                "malicious": False,
                "threats": [],
                "malicious_count": 0,
                "suspicious_count": 0,
                "error": (
                    "VirusTotal API returned status "
                    + str(response.status_code)
                    + ": "
                    + response.text
                )
            }

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        threats = []

        if malicious > 0:

            threats.append(
                str(malicious)
                + " security engine(s) flagged the URL"
            )

        if suspicious > 0:

            threats.append(
                str(suspicious)
                + " security engine(s) marked the URL suspicious"
            )

        return {
            "checked": True,

            "malicious": malicious > 0,

            "threats": threats,

            "malicious_count": malicious,

            "suspicious_count": suspicious,

            "error": None
        }

    except requests.RequestException as error:

        return {
            "checked": False,
            "malicious": False,
            "threats": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "error": str(error)
        }

    except (KeyError, TypeError, ValueError) as error:

        return {
            "checked": False,
            "malicious": False,
            "threats": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "error": (
                "Unexpected VirusTotal response: "
                + str(error)
            )
        }


if __name__ == "__main__":

    test_url = "https://example.com@google.com"

    result = check_reputation(test_url)

    print("Reputation Analysis")
    print("--------------------")

    print(
        "Checked:",
        "Yes" if result["checked"] else "No"
    )

    print(
        "Malicious:",
        "Yes" if result["malicious"] else "No"
    )

    print(
        "Threats:",
        ", ".join(result["threats"])
        if result["threats"]
        else "None"
    )

    print(
        "Malicious Engines:",
        result.get("malicious_count", 0)
    )

    print(
        "Suspicious Engines:",
        result.get("suspicious_count", 0)
    )

    if result["error"]:

        print(
            "Error:",
            result["error"]
        )
