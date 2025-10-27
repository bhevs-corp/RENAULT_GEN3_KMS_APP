# app.py
from flask import Flask, request, jsonify
from api.AES256 import TokenManager
from api.user import is_registered_user, add_user, remove_user
from api.external import call_external_sign_api, call_external_encrypt_api
import time
import logging

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
token_mgr = TokenManager()

@app.route('/users', methods=['POST'])
def register_user():
    try:
        user = request.json.get('user')
        if not user:
            logging.error('User field required')
            return jsonify({'error': 'User field required'}), 400
        if is_registered_user(user):
            logging.error(f'User already registered: {user}')
            return jsonify({'error': 'User already registered'}), 409
        if add_user(user):
            logging.info(f'User registered successfully: {user}')
            return jsonify({'message': 'User registered successfully'}), 201
        else:
            logging.error(f'Failed to register user: {user}')
            return jsonify({'error': 'Failed to register user'}), 500
    except Exception as e:
        logging.exception(f"register_user error: {e}")  # 콘솔에 에러 로그 출력
        print(f"register_user error: {e}")  # 터미널에 에러 메시지 출력
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/users/<user>', methods=['DELETE'])
def remove_user_api(user):
    if not user:
        return jsonify({'error': 'User field required'}), 400
    if not is_registered_user(user):
        return jsonify({'error': 'User not registered'}), 404
    if remove_user(user):
        return jsonify({'message': 'User removed successfully'}), 200
    else:
        return jsonify({'error': 'Failed to remove user'}), 500





@app.route('/tokens', methods=['POST'])
def get_token():
    user = request.json.get("user", "anonymous")
    if not is_registered_user(user):
        return jsonify({"error": "User not registered"}), 403
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
    except Exception:
        return jsonify({"error": "Invalid token"}), 401
    user = payload.get('user')
    exp = payload.get('exp', 0)
    if not is_registered_user(user):
        return jsonify({"error": "User not registered"}), 403
    if exp <= time.time():
        return jsonify({"error": "Token expired"}), 401
    result = call_external_sign_api(request.json)
    return jsonify(result)

@app.route('/renault/gen3/encrypt', methods=['POST'])
def encrypt_payload():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = token_mgr.decrypt(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401
    user = payload.get('user')
    exp = payload.get('exp', 0)
    if not is_registered_user(user):
        return jsonify({"error": "User not registered"}), 403
    if exp <= time.time():
        return jsonify({"error": "Token expired"}), 401
    result = call_external_encrypt_api(request.json)
    return jsonify(result)


if __name__ == '__main__':
    app.run()
