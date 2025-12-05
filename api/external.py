# api/external.py
import os
import sys
import base64
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# [SSL 패치] 르노 UAT 사설 인증서 통과용 (필수 유지)
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

# [라이브러리 로드]
try:
    from kmslib import KMSClient, MemoryTokensStore, UserAgentAppend
except ImportError:
    KMSClient = None

# --------------------------------------------------------------------------
# [Log Level 수정] 에러 원인 파악을 위해 DEBUG 모드 활성화
# --------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ExternalAPI")

# kmslib 내부 로그를 켜야 "왜" 실패했는지(404? 401?) 보입니다.
logging.getLogger("kmslib").setLevel(logging.DEBUG)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(BASE_DIR, relative_path)

# --------------------------------------------------------------------------
# KMSLib 클라이언트 관리 (Auto-Reset 추가)
# --------------------------------------------------------------------------
kms_client = None

def init_kms_client():
    global kms_client
    if not KMSClient: return

    try:
        # 1. 키 파일 경로 처리
        key_filename = os.getenv("PRIVATE_KEY", "key/private_key.pem")
        if not os.path.isabs(key_filename):
            key_path = resource_path(key_filename)
        else:
            key_path = key_filename

        # 2. URL 보정 (Okta)
        okta_url = os.getenv("API_GATEWAY", "")
        if okta_url.endswith("/v1/token"):
            okta_url = okta_url.replace("/v1/token", "")

        # 3. URL 보정 (KMS)
        kms_base_url = os.getenv("KMS_AUTHENTICATION_ENDPOINT", "")
        if "/crypto-services/v2" in kms_base_url:
            split_token = "/crypto-services/v2"
            idx = kms_base_url.find(split_token)
            kms_base_url = kms_base_url[:idx + len(split_token)]

        logger.info(f"Initializing KMS Client... (KMS URL: {kms_base_url})")

        kms_client = KMSClient(
            base_url=kms_base_url,
            base_url_okta=okta_url,
            user=os.getenv("KMS_USERNAME"),
            password=os.getenv("KMS_PASSWORD"),
            client_id=os.getenv("CLIENT_ID"),
            apikey=os.getenv("API_KEY"),
            idp_private_key=key_path,
            kid=os.getenv("KEY_ID"),
            scope=os.getenv("SCOPE", "irn-77153.cryptoAll"),
            token_store=MemoryTokensStore(
                user=os.getenv("KMS_USERNAME"),
                client_id=os.getenv("CLIENT_ID")
            ),
            http_user_agent=UserAgentAppend("BHEVS_Gen3_App/1.0")
        )
        logger.info("KMS Client Initialized.")
    except Exception as e:
        logger.error(f"KMS Init Failed: {e}")

# 최초 초기화
init_kms_client()

# --------------------------------------------------------------------------
# [핵심 로직 수정] 좀비 상태 방지 (Retry Logic)
# --------------------------------------------------------------------------
def execute_with_retry(operation_name, func, *args, **kwargs):
    global kms_client

    # 1. 클라이언트 없으면 초기화
    if not kms_client:
        init_kms_client()
        if not kms_client:
            return {"status": f"{operation_name}_fail", "data": None}

    try:
        # 2. 본래 기능 실행 시도
        return func(*args, **kwargs)
    except Exception as e:
        error_msg = str(e)
        logger.warning(f"First attempt failed ({error_msg}). Attempting reset and retry...")

        # 3. "에러 상태(Error state)"라면 과감하게 클라이언트 폐기 후 재생성
        kms_client = None
        init_kms_client()

        if not kms_client:
            return {"status": f"{operation_name}_fail", "data": None}

        try:
            # 4. 딱 한 번만 재시도 (Retry)
            return func(*args, **kwargs)
        except Exception as retry_e:
            # 두 번이나 안 되면 진짜 안 되는 것임
            logger.error(f"Retry failed: {retry_e}")
            return {"status": f"{operation_name}_fail", "data": None}

# --------------------------------------------------------------------------
# 서명 및 암호화 (Retry 래퍼 적용)
# --------------------------------------------------------------------------
def call_external_sign_api(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = payload.get("data")
    if not data: return {"status": "sign_fail", "data": None}

    def _do_sign():
        result = kms_client.sign(
            key_name=os.getenv("KEYNAME_SIGN"),
            sign_algo="RSA", hash_algo="SHA-256", pad="PSS",
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
            data_b64=data_b64, mode="CBC", pad="PKCS7"
        )

        if result.ciphertext:
            ciphertext_bin = base64.b64decode(result.ciphertext)
            return {"status": "encrypt_success", "data": {"ciphertext_bin": ciphertext_bin, "iv": result.iv}}
        return {"status": "encrypt_fail", "data": None}

    return execute_with_retry("encrypt", _do_encrypt)