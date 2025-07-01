from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
import base64
import os

app = Flask(__name__)
UPLOAD = 'uploads'
KEYS = 'keys'

os.makedirs(UPLOAD, exist_ok=True)
os.makedirs(KEYS, exist_ok=True)
os.makedirs('templates', exist_ok=True)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

@app.route('/handshake', methods=['GET'])
def handshake():
    print("✅ [HANDSHAKE] Đã gửi 'ready' cho người gửi.")
    return jsonify({"status": "ready"})

@app.route('/receive_data', methods=['POST'])
def receive_data():
    print("\n📩 [RECEIVER] Nhận gói tin từ người gửi...")
    try:
        data = request.get_json()
        if not data:
            print("❌ Không nhận được JSON hợp lệ.")
            return jsonify({"status": "NACK", "message": "Dữ liệu JSON không hợp lệ."}), 400

        iv = base64.b64decode(data['iv'])
        ciphertext = base64.b64decode(data['ciphertext'])
        signature = base64.b64decode(data['signature'])
        enc_key = base64.b64decode(data['enc_aes_key'])

        file_name = data['file_name']
        timestamp = data['timestamp']
        record_id = data['medical_record_id']
        password_hash_recv = data['password_hash']
        integrity_hash_recv = data['integrity_hash']

        # Kiểm tra mật khẩu
        passfile = os.path.join(UPLOAD, 'password_hash.txt')
        if not os.path.exists(passfile):
            print("❌ Không tìm thấy file password_hash.txt")
            return jsonify({"status": "NACK", "message": "Thiếu file password_hash.txt"})

        with open(passfile) as f:
            stored_hash = f.read().strip()

        if password_hash_recv != stored_hash:
            print("❌ Mật khẩu không đúng.")
            print("Nhận:", password_hash_recv)
            print("Đúng :", stored_hash)
            return jsonify({"status": "NACK", "message": "Mật khẩu không hợp lệ"})

        # Kiểm tra toàn vẹn
        hash_local = SHA512.new(iv + ciphertext).hexdigest()
        if hash_local != integrity_hash_recv:
            print("❌ Hash toàn vẹn không khớp.")
            return jsonify({"status": "NACK", "message": "Hash toàn vẹn không khớp"})

        # Kiểm tra chữ ký
        sender_pub_path = os.path.join(KEYS, 'sender_public.pem')
        if not os.path.exists(sender_pub_path):
            print("❌ Không tìm thấy khóa công khai người gửi.")
            return jsonify({"status": "NACK", "message": "Không có khóa công khai người gửi"})

        sender_pub = RSA.import_key(open(sender_pub_path).read())
        data_to_verify = f"{file_name}+{timestamp}+{record_id}".encode()
        h = SHA512.new(data_to_verify)

        try:
            pkcs1_15.new(sender_pub).verify(h, signature)
        except Exception as e:
            print("❌ Sai chữ ký số:", e)
            return jsonify({"status": "NACK", "message": "Sai chữ ký số"})

        print("✅ Xác thực thành công. Đang giải mã AES...")

        # Giải mã AES
        priv_path = os.path.join(KEYS, 'receiver_private.pem')
        if not os.path.exists(priv_path):
            print("❌ Không tìm thấy khóa riêng receiver.")
            return jsonify({"status": "NACK", "message": "Không có khóa riêng receiver"})

        receiver_priv = RSA.import_key(open(priv_path).read())
        aes_key = PKCS1_OAEP.new(receiver_priv).decrypt(enc_key)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext_padded)

        filepath = os.path.join(UPLOAD, 'medical_record.txt')
        with open(filepath, 'wb') as f:
            f.write(plaintext)

        print("✅ ĐÃ LƯU FILE:", filepath)
        return jsonify({"status": "ACK", "message": "Đã giải mã và lưu thành công!"})

    except Exception as e:
        print(f"❌ Lỗi toàn cục: {e}")
        return jsonify({"status": "NACK", "message": f"Lỗi xử lý: {str(e)}"})

@app.route('/')
def home():
    return render_template('receiver.html')

@app.route('/view_record', methods=['GET', 'POST'])
def view_record():
    message = ""
    record_text = None
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            message = "⚠️ Vui lòng nhập mật khẩu"
        else:
            stored_hash_path = os.path.join(UPLOAD, 'password_hash.txt')
            if os.path.exists(stored_hash_path):
                with open(stored_hash_path, 'r') as f:
                    stored_hash = f.read().strip()
                hash_input = SHA256.new(password.encode()).hexdigest()
                if hash_input == stored_hash:
                    file_path = os.path.join(UPLOAD, 'medical_record.txt')
                    if os.path.exists(file_path):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            record_text = f.read()
                    else:
                        message = "❌ Không tìm thấy file bệnh án."
                else:
                    message = "❌ Mật khẩu không đúng."
            else:
                message = "❌ Thiếu file hash mật khẩu."

    return render_template('view_record.html', message=message, record=record_text)

if __name__ == '__main__':
    print("🚀 SERVER KHỞI ĐỘNG")
    app.run(port=5001, debug=True)
