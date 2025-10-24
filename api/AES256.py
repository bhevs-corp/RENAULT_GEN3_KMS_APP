import json
import time
from Cryptodome.Cipher import AES 
from base64 import b64encode, b64decode
from config import AES_KEY, AES_IV

KEY = AES_KEY
IV = AES_IV


class TokenManager:
    def encrypt(self, payload: dict) -> str:
        data = json.dumps(payload).encode()
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        pad_len = 16 - len(data) % 16
        data_padded = data + bytes([pad_len]) * pad_len
        
        enc = cipher.encrypt(data_padded)
        token = b64encode(enc).decode()
        
        return token

    def decrypt(self, token: str) -> dict:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        enc = b64decode(token)
        data = cipher.decrypt(enc)
        pad_len = data[-1]
        data_unpadded = data[:-pad_len]
        
        decoded_payload = json.loads(data_unpadded.decode())
        return decoded_payload
