# TRIỂN KHAI HOTP/TOTP + CLI 
import base64
import hashlib
import hmac
import os
import struct
import time

# >>> TIỆN ÍCH CƠ BẢN <<<
def _int_to_bytes(value: int) -> bytes:
    # 8-byte big-endian
    return struct.pack('>Q', value)     

def _dynamic_truncate(hmac_bytes: bytes) -> int:
    # Lấy 4 bit cuối cùng làm chỉ số
    offset = hmac_bytes[-1] & 0x0F 
    # Lấy 4 byte từ vị trí đó
    part = hmac_bytes[offset:offset+4]   
    # Chuyển 4 byte thành số nguyên, bỏ bit dấu (đảm bảo số dương)
    code_int = struct.unpack('>I', part)[0] & 0x7FFFFFFF   
    return code_int

# >>> HOTP/TOTP <<<
def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    # Tính HMAC-SHA1
    mac = hmac.new(secret, _int_to_bytes(counter), hashlib.sha1).digest()
    code_int = _dynamic_truncate(mac)
    code = code_int % (10 ** digits)  # ra OTP
    return str(code).zfill(digits)    # 'zfill(digits)' đảm bảo đủ số chữ số (vd: 000123)

def totp(secret: bytes, time_step: int = 30, t0: int = 0, digits: int = 6, for_time = None) -> str:
    if for_time is None:
        for_time = int(time.time())   # 'time.time()' giây hiện tại
    counter = (for_time - t0) // time_step
    return hotp(secret, counter, digits = digits)

def verify_hotp(secret: bytes, client_code: str, counter: int, look_ahead: int = 10, digits: int = 6):
    # Cho phép trễ (look-ahead window)
    for i in range(look_ahead + 1):
        # Nếu khớp mã của client → trả về True và counter mới
        if hotp(secret, counter + i, digits=digits) == client_code:
            return True, counter + i + 1
    return False, counter

def verify_totp(secret: bytes, client_code: str, time_step: int = 30, t0: int = 0, window: int = 1, digits: int = 6, for_time = None) -> bool:
    if for_time is None:
        for_time = int(time.time())
    counter = (for_time - t0) // time_step
    # Cho phép chênh lệch ± window (thường = 1, tức là 30s trước/sau)
    for w in range(-window, window + 1):
        if totp(secret, time_step=time_step, t0=t0, digits=digits, for_time=for_time + w*time_step) == client_code:
            return True
    return False

# >>> QUẢN LÝ SECRET <<<
def random_base32_secret(length: int = 20) -> str:
    # Tạo bytes ngẫu nhiên
    raw = os.urandom(length)
    # Mã hóa Base32, loại bỏ dấu '=' padding
    return base64.b32encode(raw).decode('ascii').replace('=', '')

def b32_to_bytes(b32: str) -> bytes:
    pad = '=' * ((8 - len(b32) % 8) % 8)
    # Giải mã Base32 về bytes, thêm padding '=' nếu thiếu
    return base64.b32decode(b32 + pad, casefold=True)

# >>> QUẢN LÝ COUNTER HOTP <<<
HOTP_COUNTER_FILE = "hotp_counter.txt"   # Lưu file counter

def get_counter() -> int:   # Đọc counter từ file, nếu chưa có thì trả về 0
    if not os.path.exists(HOTP_COUNTER_FILE):
        return 0
    with open(HOTP_COUNTER_FILE) as f:
        return int(f.read().strip())

def save_counter(counter: int):   # Ghi counter mới vào file
    with open(HOTP_COUNTER_FILE, "w") as f:
        f.write(str(counter))

def create_tmp_hotp_auto(secret_bytes: bytes, digits: int = 6):   # Sinh OTP
    counter = get_counter()
    code_now = hotp(secret_bytes, counter, digits=digits)
    with open(TMP_OTP_FILE, "w") as f:
        f.write(code_now)
    print(f"[+] HOTP (counter={counter}): {code_now}")
    save_counter(counter + 1)  # tăng counter sau mỗi lần dùng
    return code_now

# >>> CLI <<<
# Thư mục lưu key + file OTP tạmtạm
KEYS_DIR = "keys"
TMP_OTP_FILE = "otp.tmp"

# Lưu secret vào file 'private.key'
def save_keys(secret_b32: str, out_dir: str = KEYS_DIR):
    os.makedirs(out_dir, exist_ok=True)
    private_path = os.path.join(out_dir, "private.key")
    public_path = os.path.join(out_dir, "public.key")

    with open(private_path, "w") as f:
        f.write(secret_b32)

    print(f"[+] Keys saved in {out_dir}: private.key, public.key")

# Sinh mã TOTP + tính thời gian còn lại (ví dụ: còn 12s nữa hết hạn)
def create_tmp_totp(secret_bytes: bytes, time_step: int = 30):
    now = int(time.time())
    code_now = totp(secret_bytes, digits=6, time_step=30, for_time=now)
    remaining = time_step - (now % time_step)
    with open(TMP_OTP_FILE, "w") as f:
        f.write(code_now)
    print(f"[+] OTP: {code_now} | valid for {remaining} seconds")
    return code_now

# Sinh HOTP theo counter
def create_tmp_hotp(secret_bytes: bytes, counter: int, digits: int = 6):
    code_now = hotp(secret_bytes, counter, digits=digits)
    with open(TMP_OTP_FILE, "w") as f:
        f.write(code_now)
    print(f"[+] HOTP (counter={counter}): {code_now}")
    return code_now

# Xóa file OTP tạm
def delete_tmp_otp():
    if os.path.exists(TMP_OTP_FILE):
        os.remove(TMP_OTP_FILE)
        print(f"[-] {TMP_OTP_FILE} deleted.")
    else:
        print("[!] No temp OTP file found.")

# Menu CLI (giao diện dòng lệnh)
def cli():
    print("=== OTP DEMO CLI ===")
    print("1. Generate new key pair")
    print("2. Create temp HOTP")
    print("3. Create temp TOTP")
    print("4. Delete temp OTP")
    print("5. Exit")

    choice = input("Choose option: ").strip()
    if choice == "1":
        secret_b32 = random_base32_secret(20)
        save_keys(secret_b32)

     
    elif choice == "2":
        try:
            with open(os.path.join(KEYS_DIR, "private.key")) as f:
                secret_b32 = f.read().strip()
            secret_bytes = b32_to_bytes(secret_b32)
            create_tmp_hotp_auto(secret_bytes)   # HOTP auto tăng
        except FileNotFoundError:
            print("[!] private.key not found. Please generate key first.")

    elif choice == "3":
        try:
            with open(os.path.join(KEYS_DIR, "private.key")) as f:
                secret_b32 = f.read().strip()
            secret_bytes = b32_to_bytes(secret_b32)
            create_tmp_totp(secret_bytes)   # TOTP
        except FileNotFoundError:
            print("[!] private.key not found. Please generate key first.")

    elif choice == "4":
        delete_tmp_otp()
    
    elif choice == "5":
        return False
    else:
        print("[!] Invalid choice.")
    return True

# Chạy CLI
if __name__ == "__main__":
    # CLI loop
    while True:
        if not cli():
            break
        print()
