from flask import Flask, jsonify
import time
import requests
import re
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


da = 'f2212101'
dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
x= [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
'72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']

def encrypt_packet(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def Decrypt_ID(da):
    if da != None and len(da) == 10:
        w= 128
        xxx =len(da)/2-1
        xxx = str(xxx)[:1]
        for i in range(int(xxx)-1):
            w =w*128
        x1 =da[:2]
        x2 =da[2:4]
        x3 =da[4:6]
        x4 =da[6:8]
        x5 =da[8:10]
        return str(w*x.index(x5)+(dec.index(x2)*128)+dec.index(x1)+(dec.index(x3)*128*128)+(dec.index(x4)*128*128*128))

    if da != None and len(da) == 8:
        w= 128
        xxx =len(da)/2-1
        xxx = str(xxx)[:1]
        for i in range(int(xxx)-1):
            w =w*128
        x1 =da[:2]
        x2 =da[2:4]
        x3 =da[4:6]
        x4 =da[6:8]
        return str(w*x.index(x4)+(dec.index(x2)*128)+dec.index(x1)+(dec.index(x3)*128*128))
    
    return None
    
def Encrypt_ID(x):
    x = int(x)
    dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx= [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
    '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x= x/128 
    if x>128:
        x =x/128
        if x >128:
            x= x/128
            if x>128:

                x= x/128
                strx= int(x)
                y= (x-int(strx))*128
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                m=(n-int(strn))*128
                return dec[int(m)]+dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]
            else:
                strx= int(x)
                y= (x-int(strx))*128
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                return dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]

def decrypt_packet(packet):
    packet = bytes.fromhex(packet)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(packet), AES.block_size)
    return plain_text.hex()


def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def Encrypt(x):
    x = int(x)
    dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx= [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
    '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x= x/128 
    if x>128:
        x =x/128
        if x >128:
            x= x/128
            if x>128:
                x= x/128
                strx= int(x)
                y= (x-int(strx))*128
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                m=(n-int(strn))*128
                return dec[int(m)]+dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]
            else:
                print(x)
                strx= int(x)
                print(strx)
                y= (x-int(strx))*128
                print(y)
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                return dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]
        else:
            strx= int(x)
            y= (x-int(strx))*128
            stry =str(int(y))
            z = (y-int(stry))*128
            strz =str(int(z))
            return dec[int(z)]+dec[int(y)]+xxx[int(x)] 
    else:
        strx= int(x)
        if strx ==0:
            wewae=2            
            y= (x-int(strx))*128
            inty =int(y)
            return  xxx[inty]
        else:
            y= (x-int(strx))*128
            stry =str(int(y))
            return dec[int(y)]+xxx[int(x)]













print(decrypt_api(b'\xb7C\x1bG\xb8u\x8b\xec\xad\x82\x9c\xa9)\xe3\xde)'.hex()))

print(Encrypt_ID(270279853))

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
