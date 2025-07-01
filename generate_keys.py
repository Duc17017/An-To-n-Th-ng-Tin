from Crypto.PublicKey import RSA
import os

KEY_FOLDER = 'keys'
os.makedirs(KEY_FOLDER, exist_ok=True)

# Sender
sender_key = RSA.generate(2048)
with open(os.path.join(KEY_FOLDER, 'sender_private.pem'), 'wb') as f:
    f.write(sender_key.export_key())
with open(os.path.join(KEY_FOLDER, 'sender_public.pem'), 'wb') as f:
    f.write(sender_key.publickey().export_key())

# Receiver
receiver_key = RSA.generate(2048)
with open(os.path.join(KEY_FOLDER, 'receiver_private.pem'), 'wb') as f:
    f.write(receiver_key.export_key())
with open(os.path.join(KEY_FOLDER, 'receiver_public.pem'), 'wb') as f:
    f.write(receiver_key.publickey().export_key())

print("Keys generated successfully.")
