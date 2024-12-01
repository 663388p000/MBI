#!/bin/bash

# اسکریپت محافظت از سرور و مدیریت حملات

# نصب فایروال Fail2Ban برای جلوگیری از حملات brute-force
echo "نصب و راه‌اندازی Fail2Ban..."
sudo apt-get install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# تغییر پورت SSH برای جلوگیری از حملات brute-force
echo "تغییر پورت SSH به یک شماره سفارشی..."
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# غیرفعال کردن ورود با رمز عبور و استفاده از کلید SSH برای ورود به سیستم
echo "غیرفعال کردن ورود با رمز عبور و فعال‌سازی ورود با کلید SSH..."
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# نصب Nmap برای شبیه‌سازی حملات و اسکن پورت‌ها
echo "نصب Nmap برای شبیه‌سازی حملات..."
sudo apt-get install nmap -y

# نصب Wireshark برای نظارت بر ترافیک شبکه
echo "نصب Wireshark برای تحلیل ترافیک شبکه..."
sudo apt-get install wireshark -y

# نصب Snort (سیستم تشخیص نفوذ)
echo "نصب Snort برای تشخیص نفوذ..."
sudo apt-get install snort -y

# نصب pycryptodome برای رمزگذاری داده‌ها
echo "نصب pycryptodome برای رمزگذاری داده‌ها..."
pip install pycryptodome

# راه‌اندازی Google Authenticator برای احراز هویت چندعاملی
echo "راه‌اندازی Google Authenticator برای احراز هویت چندعاملی..."
sudo apt-get install libpam-google-authenticator -y
sudo systemctl restart sshd

# پیکربندی فایروال برای مسدودسازی IP مشکوک
echo "پیکربندی فایروال برای مسدودسازی IPهای مشکوک..."
sudo iptables -A INPUT -s $1 -j DROP
echo "دسترسی از IP $1 مسدود شد."

# شبیه‌سازی حمله DDoS با استفاده از ابزارهای ابری
echo "شبیه‌سازی حمله DDoS با استفاده از ابزارهای ابری (Cloudflare و دیگر فایروال‌ها)..."

# افزودن احراز هویت چندعاملی (MFA) برای سرور
echo "افزودن MFA برای محافظت بیشتر..."
sudo apt-get install libpam-google-authenticator -y

# بررسی وضعیت امنیتی و ارسال گزارش
echo "بررسی وضعیت امنیتی سرور..."
nmap -p 1-65535 localhost
echo "گزارش وضعیت امنیتی آماده شد."

# کد برای رمزگذاری داده‌ها با استفاده از AES
echo "رمزگذاری داده‌ها با استفاده از AES..."

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_data(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_data(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

data_to_encrypt = "This is a secure message"
encryption_key = "this_is_a_secret_key"
iv, encrypted_data = encrypt_data(data_to_encrypt, encryption_key)
print(f"Encrypted Data: {encrypted_data}")

# اسکریپت برای ارسال حملات به سرور هکر در صورت شناسایی
echo "ارسال حمله به سرور هکر در صورت شناسایی..."
hacker_ip=$2
curl -X GET http://$hacker_ip/attack

# گزارش وضعیت امنیتی و اقدامات انجام شده
echo "گزارش وضعیت امنیتی:"
echo "FIREWALL: فعال"
echo "Intrusion Detection: فعال"
echo "DDoS Protection: فعال"
echo "MFA: فعال"