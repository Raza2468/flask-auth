import binascii
from Crypto.Cipher import AES
import base64
from datetime import datetime

class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key[:32].ljust(32, '\0').encode()

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(raw.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt(self, enc):
        missing_padding = len(enc) % 4
        if missing_padding:
            enc += '=' * (4 - missing_padding)  # Add necessary padding
        try:
            enc = base64.b64decode(enc)
        except binascii.Error as e:
            raise ValueError("Invalid base64 string") from e
        
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = cipher.decrypt(enc).decode()
        return self._unpad(decrypted)

    def encrypt_date(self, date_obj):
        """Encrypt a date object."""
        date_str = date_obj.strftime('%Y-%m-%d')  # Convert date to string
        return self.encrypt(date_str)

    def decrypt_date(self, encrypted_date):
        """Decrypt an encrypted date."""
        date_str = self.decrypt(encrypted_date)
        return datetime.strptime(date_str, '%Y-%m-%d').date()  # Convert string back to date object

    def _pad(self, s):
        padding = self.bs - (len(s) % self.bs)
        return s + (chr(padding) * padding)


    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]
