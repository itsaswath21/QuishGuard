import cv2
from pyzbar.pyzbar import decode
from url_checker import is_url, analyze_url


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
                "Risk Score:",
                analysis["risk_score"],
                "/ 100"
            )

            print("Verdict:", analysis["verdict"])

            print()
            print("Reasons:")

            for reason in analysis["reasons"]:
                print("-", reason)

        else:
            print("This is not a URL.")