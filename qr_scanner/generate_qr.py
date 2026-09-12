import qrcode

data = "http://192.168.1.50/login"

qr = qrcode.make(data)

qr.save("qr_scanner/qr.png")

print("QR code created successfully!")