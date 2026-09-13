import qrcode

data = "https://example.com"

qr = qrcode.make(data)

qr.save("qr_scanner/qr.png")

print("QR code created successfully!")