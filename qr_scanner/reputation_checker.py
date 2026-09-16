import os
import requests
from dotenv import load_dotenv


load_dotenv()


VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"


def check_reputation(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "checked": False,
            "malicious": False,
            "threats": [],
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.post(
            VIRUSTOTAL_URL,
            headers=headers,
            data={
                "url": url
            },
            timeout=10
        )

        if response.status_code not in [200, 201]:
            return {
                "checked": False,
                "malicious": False,
                "threats": [],
                "error": "VirusTotal API returned status "
                         + str(response.status_code)
                         + ": "
                         + response.text
            }

        data = response.json()

        analysis_id = data["data"]["id"]

        analysis_url = (
            "https://www.virustotal.com/api/v3/analyses/"
            + analysis_id
        )

        analysis_response = requests.get(
            analysis_url,
            headers=headers,
            timeout=10
        )

        if analysis_response.status_code != 200:
            return {
                "checked": False,
                "malicious": False,
                "threats": [],
                "error": "VirusTotal analysis request returned status "
                         + str(analysis_response.status_code)
            }

        analysis_data = analysis_response.json()

        stats = analysis_data["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        threats = []

        if malicious > 0:
            threats.append(
                str(malicious) + " security engine(s) flagged the URL"
            )

        if suspicious > 0:
            threats.append(
                str(suspicious) + " security engine(s) marked the URL suspicious"
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
            "error": str(error)
        }

    except (KeyError, TypeError, ValueError) as error:
        return {
            "checked": False,
            "malicious": False,
            "threats": [],
            "error": "Unexpected VirusTotal response: " + str(error)
        }


if __name__ == "__main__":
    test_url = "https://example.com"

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

    if result.get("malicious_count") is not None:
        print(
            "Malicious Engines:",
            result["malicious_count"]
        )

    if result.get("suspicious_count") is not None:
        print(
            "Suspicious Engines:",
            result["suspicious_count"]
        )

    if result["error"]:
        print("Error:", result["error"])