# api/external.py
import requests

def call_external_sign_api(payload):
    # 외부 서명 API 호출 로직
    # response = requests.post('https://external.api/sign', json=payload)
    # return response.json()
    return {"status": "sign_success", "data": payload}

def call_external_encrypt_api(payload):
    # 외부 암호화 API 호출 로직
    # response = requests.post('https://external.api/encrypt', json=payload)
    # return response.json()
    return {"status": "encrypt_success", "data": payload}
