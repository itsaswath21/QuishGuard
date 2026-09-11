import cv2
from pyzbar.pyzbar import decode

image = cv2.imread("qr_scanner/qr.png")

results = decode(image)

if not results:
    print("No QR code detected.")
else:
    for result in results:
        data = result.data.decode("utf-8")
        print("QR Code detected!")
        print("Content:", data)