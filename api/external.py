# api/external.py
import os
import sys
import base64
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# SSL Patch
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def force_no_ssl_verify():
    old_request = requests.Session.request
    def new_request(self, method, url, *args, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, *args, **kwargs)
    requests.Session.request = new_request

force_no_ssl_verify()

# Library Load
try:
    from kmslib import KMSClient, MemoryTokensStore, UserAgentAppend
except ImportError:
    KMSClient = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ExternalAPI")

logging.getLogger("kmslib").setLevel(logging.DEBUG)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(BASE_DIR, relative_path)

kms_client = None

def init_kms_client():
    global kms_client
    if not KMSClient: return

    try:
        key_filename = os.getenv("PRIVATE_KEY", "key/private_key.pem")
        if not os.path.isabs(key_filename):
            key_path = resource_path(key_filename)
        else:
            key_path = key_filename

        host = os.getenv("HOST")
        logger.info(f"Initializing KMS Client... (KMS URL: {host})")

        kms_client = KMSClient(
            base_url=host,
            base_url_okta=os.getenv("OKTA_HOST"),
            user=os.getenv("KMS_USERNAME"),
            password=os.getenv("KMS_PASSWORD"),
            client_id=os.getenv("CLIENT_ID"),
            apikey=os.getenv("API_KEY"),
            idp_private_key=key_path,
            kid=os.getenv("KEY_ID"),
            scope=os.getenv("SCOPE"),
            token_store=MemoryTokensStore(
                user=os.getenv("KMS_USERNAME"),
                client_id=os.getenv("CLIENT_ID")
            )
            ,http_user_agent=UserAgentAppend(os.getenv("HTTP_USER_AGENT"))
        )
        logger.info("KMS Client Initialized.")
    except Exception as e:
        logger.error(f"KMS Init Failed: {e}")

init_kms_client()

def execute_with_retry(operation_name, func, *args, **kwargs):
    global kms_client

    if not kms_client:
        init_kms_client()
        if not kms_client:
            return {"status": f"{operation_name}_fail", "data": None}

    try:
        return func(*args, **kwargs)
    except Exception as e:
        error_msg = str(e)
        logger.warning(f"First attempt failed ({error_msg}). Attempting reset and retry...")

        kms_client = None
        init_kms_client()

        if not kms_client:
            return {"status": f"{operation_name}_fail", "data": None}

        try:
            return func(*args, **kwargs)
        except Exception as retry_e:
            logger.error(f"Retry failed: {retry_e}")
            return {"status": f"{operation_name}_fail", "data": None}

def call_external_sign_api(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = payload.get("data")
    if not data: return {"status": "sign_fail", "data": None}

    def _do_sign():
        result = kms_client.sign(
            key_name=os.getenv("KEYNAME_SIGN"),
            sign_algo=os.getenv("SIGN_ALGO"),
            hash_algo=os.getenv("HASH_ALGO"),
            pad=os.getenv("PAD"),
            salt_length=os.getenv("SALT_LENGTH"),
            data_to_sign=data
        )
        return {"status": "sign_success", "data": result.data}

    return execute_with_retry("sign", _do_sign)

def call_external_encrypt_api(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = payload.get("data")
    if not data: return {"status": "encrypt_fail", "data": None}

    def _do_encrypt():
        if isinstance(data, bytes):
            data_b64 = base64.b64encode(data).decode('utf-8')
        else:
            data_b64 = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        result = kms_client.encrypt_aes(
            key_name=os.getenv("KEYNAME_ENCRYPT"),
            data_b64=data_b64,
            mode=os.getenv("ENCRYPT_MODE"),
            pad=os.getenv("ENCRYPT_PAD")
        )

        if result.ciphertext:
            ciphertext_bin = base64.b64decode(result.ciphertext)
            return {"status": "encrypt_success", "data": {"ciphertext_bin": ciphertext_bin, "iv": result.iv}}
        return {"status": "encrypt_fail", "data": None}

    return execute_with_retry("encrypt", _do_encrypt)