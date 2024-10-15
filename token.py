from flask import Flask, jsonify
import time
import requests
import re
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

def convert_to_hex(PAYLOAD):
    hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
    return hex_payload

def convert_to_bytes(PAYLOAD):
    payload = bytes.fromhex(PAYLOAD)
    return payload

def get_tokens():
    url = 'https://hasaki.io.vn/tests/test.php'
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        accounts = data[:101]  # Lấy 101 tài khoản đầu tiên
        ids = [account['id'] for account in accounts]  # Lấy tất cả các id
        passwords = [account['password'] for account in accounts]  # Lấy tất cả các password
        return ids, passwords
    return [], []

def guest_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": f"{uid}",
        "password": f"{password}",
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    response = requests.post(url, headers=headers, data=data)
    data = response.json()
    NEW_ACCESS_TOKEN = data['access_token']
    NEW_OPEN_ID = data['open_id']
    OLD_ACCESS_TOKEN = "37c00ba521e42f7fb8e374a2b5d07c2417e054abca6d7e0f25a83a8243f1d00a"
    OLD_OPEN_ID = "c5a8e6bfd6ff9246a9cc4e043f7f5753"
    return TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    PYLOAD = b'C\xb9\xed\x02\xee;\xe0W6\xe1\xd6&\x9d4Q3\xb3\xb4\x92\xa6\xae\xcf\x16\xfe\xf4\x9e\xe3R\x99h%\xee~I_...'
    a = convert_to_hex(PYLOAD)
    data = bytes.fromhex(decrypt_api(a))
    data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
    d = encrypt_api(data.hex())
    Final_Payload = convert_to_bytes(d)
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        "Expect": "100-continue",
        "Authorization": "Bearer ",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB46",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(Final_Payload.hex())),
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "loginbp.common.ggbluefox.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }
    
    RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
    BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
    result = re.split(r'[^a-zA-Z0-9\s\.]', BASE64_TOKEN)
    rs_token = [x for x in result if x]
    if rs_token:
        return rs_token[0]
    return None

def get_all_tokens_parallel(ids, passwords):
    tokens = []
    with ThreadPoolExecutor(max_workers=50) as executor:  # Sử dụng 50 luồng để tăng tốc
        futures = []
        for uid, password in zip(ids, passwords):
            futures.append(executor.submit(guest_token, uid, password))
            time.sleep(0.050)
        
        for future in futures:
            token = future.result()
            if token:
                tokens.append(token)

    return tokens

@app.route('/get-tokens', methods=['GET'])
def run_threads():
    ids, passwords = get_tokens()  # Lấy danh sách ID và password từ API trước
    tokens = get_all_tokens_parallel(ids, passwords)  # Lấy token song song
    
    if tokens:
        response = {"tokens": [f"token{i+1}: {token}" for i, token in enumerate(tokens)]}
        return jsonify(response), 200
    else:
        return jsonify({"message": "Không có token để xử lý!"}), 400

if __name__ == "__main__":
    app.run(debug=True)
