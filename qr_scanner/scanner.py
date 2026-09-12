import cv2
from pyzbar.pyzbar import decode
from url_checker import is_url, check_https

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
            print("This is a URL.")

            if check_https(data):
                print("HTTPS: Secure connection")
            else:
                print("HTTPS: Not used")
        else:
            print("This is not a URL.")