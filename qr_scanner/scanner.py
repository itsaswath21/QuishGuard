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

            print(
                "HTTPS:",
                "Yes" if analysis["https"] else "No"
            )

            print(
                "IP Address:",
                "Yes" if analysis["ip_address"] else "No"
            )

            print(
                "Suspicious Keywords:",
                ", ".join(analysis["suspicious_keywords"])
                if analysis["suspicious_keywords"]
                else "None"
            )

            print(
                "Long URL:",
                "Yes" if analysis["url_length"] else "No"
            )

            print(
                "Subdomains:",
                analysis["subdomains"]
            )

            print(
                "Many Hyphens:",
                "Yes" if analysis["many_hyphens"] else "No"
            )

            print(
                "@ Symbol:",
                "Yes" if analysis["at_symbol"] else "No"
            )

            print(
                "Encoded Characters:",
                "Yes" if analysis["encoded_characters"] else "No"
            )

            print()
            print("Domain Analysis")
            print("--------------------")

            print(
                "Domain:",
                domain_analysis["domain"]
            )

            print(
                "Subdomain:",
                domain_analysis["subdomain"]
                if domain_analysis["subdomain"]
                else "None"
            )

            print()
            print("Risk Score:", analysis["risk_score"], "/ 100")
            print("Verdict:", analysis["verdict"])

            print()
            print("Reasons:")

            for reason in analysis["reasons"]:
                print("-", reason)

        else:
            print("This is not a URL.")