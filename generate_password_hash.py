# generate_password_hash.py
from Crypto.Hash import SHA256

password = '123456'  # <-- thay bằng mật khẩu thật
hash_obj = SHA256.new(password.encode())
with open('uploads/password_hash.txt', 'w') as f:
    f.write(hash_obj.hexdigest())

print("✅ Đã tạo xong password_hash.txt")
