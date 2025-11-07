# api/external.py
import os
import time
import uuid
import base64
import json
import logging
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import sys

# 상수 분리
ENV_PATH: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
SIGN_ENDPOINT_TEMPLATE: str = "https://apis-qa.renault.com/kms/crypto-services/v2/crypto/sign?keyName={key_name}&signAlgo=RSA&hashAlgo=none&pad=PSSWithPrecomputedHash&saltLength=-2"
ENCRYPT_ENDPOINT: str = "https://apis-qa.renault.com/kms/crypto-services/v2/crypto/encrypt"

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_environment(env_path: str = ENV_PATH) -> None:
    load_dotenv(env_path)

def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(key, default)

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def load_private_key(key_path: str, password: Optional[str]) -> Optional[Any]:
    try:
        key_path = resource_path(key_path)
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
        logger.info(f"Loaded private key from {key_path}")
        return private_key
    except Exception as e:
        logger.error(f"Failed to load private key: {e}")
        return None

def create_jwt(private_key: Any, key_id: str, client_id: str, audience: str) -> Optional[str]:
    try:
        now = int(time.time())
        header = {"kid": key_id, "alg": "RS256"}
        payload = {
            "aud": audience,
            "exp": now + 3600,
            "iss": client_id,
            "sub": client_id,
            "iat": now,
            "jti": str(uuid.uuid4())
        }
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        jwt = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
        logger.info("JWT created successfully")
        return jwt
    except Exception as e:
        logger.error(f"Failed to create JWT: {e}")
        return None

def get_access_token(api_gateway: str, scope: str, client_assertion: str) -> Optional[str]:
    data = {
        "grant_type": "client_credentials",
        "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "sso-uat.renault.com"
    }
    try:
        resp = requests.post(api_gateway, data=data, headers=headers, verify=False)
        if resp.status_code != 200:
            logger.error(f"Failed to get access token: {resp.text}")
            return None
        logger.info("Access token acquired successfully")
        return resp.json().get("access_token")
    except Exception as e:
        logger.error(f"Exception in get_access_token: {e}")
        return None

def get_kms_jwt(kms_auth_endpoint: str, access_token: str, api_key: str, username: str, password: str) -> Optional[str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "apikey": api_key
    }
    data = {
        "grant_type": "password",
        "username": username,
        "password": password
    }
    try:
        resp = requests.post(kms_auth_endpoint, headers=headers, json=data, verify=False)
        if resp.status_code != 200:
            logger.error(f"Failed to get KMS JWT: {resp.text}")
            return None
        logger.info("KMS JWT acquired successfully")
        return resp.json().get("jwt")
    except Exception as e:
        logger.error(f"Exception in get_kms_jwt: {e}")
        return None

def get_kms_session(mode: str) -> Optional[Dict[str, Any]]:
    load_environment()
    if mode == "sign":
        key_name = get_env("KEYNAME_SIGN")
    elif mode == "encrypt":
        key_name = get_env("KEYNAME_ENCRYPT")
    else:
        logger.error(f"Invalid mode for get_kms_session: {mode}")
        return None
    key_id = get_env("KEY_ID")
    client_id = get_env("CLIENT_ID")
    api_key = get_env("API_KEY")
    private_key_path = get_env("PRIVATE_KEY")
    private_key_password = get_env("PRIVATE_KEY_PASSWORD")
    api_gateway = get_env("API_GATEWAY")
    kms_auth_endpoint = get_env("KMS_AUTHENTICATION_ENDPOINT")
    username = get_env("KMS_USERNAME")
    password = get_env("KMS_PASSWORD")
    scope = get_env("SCOPE")
    if not all([key_name, key_id, client_id, api_key, private_key_path, scope, api_gateway, kms_auth_endpoint, username, password]):
        logger.error("Missing required environment variables for KMS session")
        return None
    if private_key_password:
        private_key = load_private_key(private_key_path, private_key_password)
    else:
        private_key = load_private_key(private_key_path, None)
    if not private_key:
        return None
    client_assertion = create_jwt(private_key, key_id, client_id, api_gateway)
    if not client_assertion:
        return None
    access_token = get_access_token(api_gateway, scope, client_assertion)
    if not access_token:
        return None
    kms_jwt = get_kms_jwt(kms_auth_endpoint, access_token, api_key, username, password)
    if not kms_jwt:
        return None
    logger.info(f"KMS {mode} session established successfully")
    return {
        "key_name": key_name,
        "api_key": api_key,
        "access_token": access_token,
        "kms_jwt": kms_jwt
    }

def sign_with_kms(data: bytes) -> Optional[Dict[str, Any]]:
    session = get_kms_session("sign")
    if not session:
        logger.error("KMS sign session not established")
        return None
    sign_endpoint = get_env("SIGN_ENDPOINT")
    headers = {
        "Content-Type": "application/octet-stream",
        "Accept": "application/json",
        "Authorization": f"Bearer {session['access_token']}",
        "KMS-Authorization": session["kms_jwt"],
        "apikey": session["api_key"]
    }
    try:
        resp = requests.post(sign_endpoint, headers=headers, data=data, verify=False)
        if resp.status_code != 200:
            logger.error(f"Sign API failed: {resp.text}")
            return None
        logger.info("Sign API call successful")
        return resp.json()
    except Exception as e:
        logger.error(f"Exception in sign_with_kms: {e}")
        return None

def encrypt_with_kms(data: bytes) -> Optional[Dict[str, Any]]:
    session = get_kms_session("encrypt")
    if not session:
        logger.error("KMS encrypt session not established")
        return None
    encryption_endpoint = get_env("ENCRYPTION_ENDPOINT")
    iv = get_env("IV")
    if not iv:
        logger.error("IV not set in environment")
        return None
    try:
        plaintext_b64 = base64.b64encode(data).decode("utf-8")
        logger.info(f"Base64-encoded input data for encryption (length={len(data)})")
    except Exception as e:
        logger.error(f"Failed to base64-encode input data: {e}")
        return None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {session['access_token']}",
        "KMS-Authorization": session["kms_jwt"],
        "apikey": session["api_key"]
    }
    data_json = {
        "id": session["key_name"],
        "plaintext": plaintext_b64,
        "mode": "CBC",
        "iv": iv,
        "pad": "none"
    }
    try:
        resp = requests.post(encryption_endpoint, headers=headers, json=data_json, verify=False)
        logger.info(f"KMS encrypt API response status: {resp.status_code}")
        logger.info(f"KMS encrypt API response text: {resp.text[:500]}")
        if resp.status_code != 200:
            logger.error(f"Encrypt API failed: {resp.text}")
            return None
        result = resp.json()
        ciphertext_b64 = result.get("ciphertext")
        logger.info(f"KMS encrypt API ciphertext (base64, first 100 chars): {str(ciphertext_b64)[:100]}")
        if not ciphertext_b64:
            logger.error("No ciphertext in encrypt API response")
            return None
        try:
            ciphertext_bin = base64.b64decode(ciphertext_b64)
            logger.info(f"Decoded ciphertext length: {len(ciphertext_bin)}")
        except Exception as e:
            logger.error(f"Failed to decode ciphertext: {e}")
            return None
        logger.info("Encryption completed successfully and ciphertext binary returned")
        return {"status": "encrypt_success", "data": ciphertext_bin}
    except Exception as e:
        logger.error(f"Exception in encrypt_with_kms: {e}")
        return None

def call_external_sign_api(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    data = payload.get("data")
    if not data:
        logger.error("No data provided for signing")
        return {"status": "sign_fail", "data": None}
    result = sign_with_kms(data)

    logger.info(f"sign_with_kms result: {result}")

    signature_b64 = result.get("data") if result else None
    if not signature_b64:
        logger.error("Signing failed or no data in response")
        return {"status": "sign_fail", "data": None}
    logger.info("Signing completed successfully")
    return {"status": "sign_success", "data": signature_b64}

def call_external_encrypt_api(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    data = payload.get("data")
    if not data:
        logger.error("No data provided for encryption")
        return {"status": "encrypt_fail", "data": None}
    logger.info(f"call_external_encrypt_api: input data length: {len(data) if hasattr(data, '__len__') else 'unknown'}")
    result = encrypt_with_kms(data)
    if not result or result.get("status") != "encrypt_success":
        logger.error("Encryption failed or no data in response")
        return {"status": "encrypt_fail", "data": None}
    logger.info("Encryption completed successfully")
    ciphertext_bin = result.get("data")
    import base64
    if isinstance(ciphertext_bin, bytes):
        ciphertext_b64 = base64.b64encode(ciphertext_bin).decode("utf-8")
        logger.info(f"call_external_encrypt_api: ciphertext_b64 length: {len(ciphertext_b64)}")
    else:
        ciphertext_b64 = ciphertext_bin
    return {"status": "encrypt_success", "data": ciphertext_b64}
