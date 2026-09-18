import cv2
from pyzbar.pyzbar import decode

from url_checker import is_url, analyze_url
from domain_checker import analyze_domain


image = cv2.imread("qr_scanner/qr.png")

results = decode(image)

if not results:
    print("No QR code detected.")
else:
    for result in results:
        data = result.data.decode("utf-8")

        print("QR Code detected!")
        print("Content:", data)

        if is_url(data):
            analysis = analyze_url(data)
            domain_analysis = analyze_domain(data)

            print()
            print("URL Analysis")
            print("--------------------")

            print("HTTPS:", "Yes" if analysis["https"] else "No")
            print("IP Address:", "Yes" if analysis["ip_address"] else "No")

            print(
                "Suspicious Keywords:",
                ", ".join(analysis["suspicious_keywords"])
                if analysis["suspicious_keywords"]
                else "None"
            )

            print("Long URL:", "Yes" if analysis["url_length"] else "No")
            print("Subdomains:", analysis["subdomains"])

            print(
                "Many Hyphens:",
                "Yes" if analysis["many_hyphens"] else "No"
            )

            print("@ Symbol:", "Yes" if analysis["at_symbol"] else "No")

            print(
                "@ Destination:",
                analysis["at_symbol_destination"]
                if analysis["at_symbol_destination"]
                else "None"
            )

            print(
                "Deceptive @ Pattern:",
                "Yes" if analysis["deceptive_at_symbol"]
                else "No"
            )

            print(
                "Encoded Characters:",
                "Yes" if analysis["encoded_characters"]
                else "No"
            )

            print(
                "Domain Age:",
                str(analysis["domain_age_years"]) + " years"
                if analysis["domain_age_years"] is not None
                else "Unavailable"
            )

            print("Domain Age Risk:", "+" + str(analysis["domain_age_risk"]))

            print(
                "Homoglyph Detection:",
                "Suspicious"
                if analysis["homoglyph_suspicious"]
                else "Normal"
            )

            print()
            print("Redirect Analysis")
            print("--------------------")

            print("Redirect Count:", analysis["redirect_count"])
            print("Redirect Risk:", "+" + str(analysis["redirect_risk"]))
            print("Final URL:", analysis["final_url"])

            print()
            print("Domain Analysis")
            print("--------------------")

            print("Domain:", domain_analysis["domain"])

            print(
                "Subdomain:",
                domain_analysis["subdomain"]
                if domain_analysis["subdomain"]
                else "None"
            )

            print()
            print("VirusTotal Reputation Analysis")
            print("--------------------")

            print(
                "Checked:",
                "Yes" if analysis["reputation_checked"]
                else "No"
            )

            print(
                "Malicious:",
                "Yes" if analysis["reputation_malicious"]
                else "No"
            )

            print(
                "Threats:",
                ", ".join(analysis["reputation_threats"])
                if analysis["reputation_threats"]
                else "None"
            )

            print("Reputation Risk:", "+" + str(analysis["reputation_risk"]))

            if analysis["reputation_error"]:
                print(
                    "Status:",
                    "VirusTotal reputation check unavailable"
                )

            print()
            print("====================")
            print("FINAL SECURITY RESULT")
            print("====================")

            print("Risk Score:", analysis["risk_score"], "/ 100")
            print("Verdict:", analysis["verdict"])

            print()
            print("Reasons")
            print("--------------------")

            if analysis["reasons"]:
                for reason in analysis["reasons"]:
                    print("-", reason)
            else:
                print("- No suspicious indicators detected.")

        else:
            print()
            print("This is not a URL.")