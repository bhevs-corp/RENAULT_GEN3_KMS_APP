# app.py
from flask import Flask, request, jsonify, send_file
from api.AES256 import TokenManager
from api.user import is_registered_user, add_user, remove_user
from api.external import call_external_sign_api, call_external_encrypt_api
import time
import logging
import io
import base64

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
token_mgr = TokenManager()

def handle_user_exception(e, context=""):
    try:
        logging.exception(f"{context} error: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    except Exception as ex:
        logging.error(f"Exception in handle_user_exception: {ex}")
        return '{"error": "Critical server error"}', 500, {'Content-Type': 'application/json'}

def validate_token_and_user(payload):
    user = payload.get('user')
    exp = payload.get('exp', 0)
    if not is_registered_user(user):
        return jsonify({"error": "User not registered"}), 403
    if exp <= time.time():
        return jsonify({"error": "Token expired"}), 401
    return None

def validate_user_existence(user, required=True, not_registered_code=404):
    if required and not user:
        return jsonify({'error': 'User field required'}), 400
    if not is_registered_user(user):
        return jsonify({'error': 'User not registered'}), not_registered_code
    return None

def register_user_with_check(user):
    if is_registered_user(user):
        logging.error(f'User already registered: {user}')
        return jsonify({'error': 'User already registered'}), 409
    if add_user(user):
        logging.info(f'User registered successfully: {user}')
        return jsonify({'message': 'User registered successfully'}), 201
    else:
        logging.error(f'Failed to register user: {user}')
        return jsonify({'error': 'Failed to register user'}), 500




@app.route('/users', methods=['POST'])
def register_user():
    try:
        user = request.json.get('user')
        check = validate_user_existence(user, required=True, not_registered_code=200)
        if check and check[1] == 400:  # 필수 입력만 체크
            return check
        return register_user_with_check(user)
    except Exception as e:
        return handle_user_exception(e, "register_user")

@app.route('/users/<user>', methods=['DELETE'])
def remove_user_api(user):
    check = validate_user_existence(user, required=True, not_registered_code=404)
    if check:
        return check
    if remove_user(user):
        return jsonify({'message': 'User removed successfully'}), 200
    else:
        return jsonify({'error': 'Failed to remove user'}), 500





@app.route('/tokens', methods=['POST'])
def get_token():
    user = request.json.get("user", "anonymous")
    check = validate_user_existence(user, required=True, not_registered_code=403)
    if check:
        return check
    exp = time.time() + 3600
    payload = {
        "exp": exp,
        "user": user
    }
    token = token_mgr.encrypt(payload)
    return jsonify({"token": token, "exp": exp})





@app.route('/renault/gen3/sign', methods=['POST'])
def external_api():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = token_mgr.decrypt(token)
    except Exception as e:
        return handle_user_exception(e, "external_api (token decrypt)")
    check = validate_token_and_user(payload)
    if check:
        return check
    try:
        result = call_external_sign_api(request.json)
        return jsonify(result)
    except Exception as e:
        return handle_user_exception(e, "external_api (sign)")

@app.route('/renault/gen3/encrypt', methods=['POST'])
def encrypt_payload():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = token_mgr.decrypt(token)
    except Exception as e:
        return handle_user_exception(e, "encrypt_payload (token decrypt)")
    check = validate_token_and_user(payload)
    if check:
        return check
    try:
        if 'data' in request.files:
            file = request.files['data']
            file_bytes = file.read()
            orig_filename = file.filename or "encrypted.bin"
            if "." in orig_filename:
                name, ext = orig_filename.rsplit('.', 1)
                encrypted_filename = f"{name}_Encrypted.{ext}"
            else:
                encrypted_filename = orig_filename + "_Encrypted"
            payload_dict = {"data": file_bytes}
            result = call_external_encrypt_api(payload_dict)
            ciphertext_bytes = base64.b64decode(result["data"])
            return send_file(
                io.BytesIO(ciphertext_bytes),
                as_attachment=True,
                download_name=encrypted_filename,
                mimetype="application/octet-stream"
            )
        else:
            result = call_external_encrypt_api(request.json)
            return jsonify(result)
    except Exception as e:
        return handle_user_exception(e, "encrypt_payload (encrypt)")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=32511)
