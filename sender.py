from flask import Flask, render_template, request, flash, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
import base64
import os
import datetime
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

KEY_FOLDER = 'keys'
SERVER_URL = 'http://localhost:5001'

sender_private_key = RSA.import_key(open(os.path.join(KEY_FOLDER, 'sender_private.pem')).read())
receiver_public_key = RSA.import_key(open(os.path.join(KEY_FOLDER, 'receiver_public.pem')).read())

@app.route('/', methods=['GET', 'POST'])
def send_medical_record():
    if request.method == 'POST':
        medical_record = request.form['medical_record']
        password = request.form['password']

        try:
            r = requests.get(f"{SERVER_URL}/handshake")
            if r.status_code != 200 or r.json().get('status') != 'ready':
                flash("Không thể bắt tay với server", "error")
                return redirect(url_for('send_medical_record'))
        except Exception as e:
            flash(f"Lỗi kết nối server: {str(e)}", "error")
            return redirect(url_for('send_medical_record'))

        file_name = "medical_record.txt"
        timestamp = datetime.datetime.utcnow().isoformat()
        medical_record_id = "MR123456"

        plaintext = medical_record.encode('utf-8')
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        pad_len = AES.block_size - len(plaintext) % AES.block_size
        padded = plaintext + bytes([pad_len] * pad_len)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(padded)

        h_integrity = SHA512.new(iv + ciphertext).hexdigest()
        to_sign = f"{file_name}+{timestamp}+{medical_record_id}".encode()
        h_sign = SHA512.new(to_sign)
        signature = pkcs1_15.new(sender_private_key).sign(h_sign)

        password_hash = SHA256.new(password.encode()).hexdigest()
        cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
        enc_aes_key = cipher_rsa.encrypt(aes_key)

        payload = {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "integrity_hash": h_integrity,
            "signature": base64.b64encode(signature).decode(),
            "password_hash": password_hash,
            "enc_aes_key": base64.b64encode(enc_aes_key).decode(),
            "file_name": file_name,
            "timestamp": timestamp,
            "medical_record_id": medical_record_id
        }

        try:
            resp = requests.post(f"{SERVER_URL}/receive_data", json=payload)
            if resp.json().get('status') == 'ACK':
                flash("✅ Gửi bệnh án thành công!", "success")
            else:
                flash(f"❌ Lỗi: {resp.json().get('message')}", "error")
        except Exception as e:
            flash(f"Lỗi khi gửi dữ liệu: {e}", "error")

        return redirect(url_for('send_medical_record'))

    return render_template('send_medical_record.html')

if __name__ == '__main__':
    app.run(port=5000, debug=True)
