from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import hashlib
import base64
import secrets

app = Flask(__name__)

# ---------- ROUTES ----------
@app.route('/')
def default_redirect():
    return render_template('roothome.html')

@app.route('/roothome')
def roothome_page():
    return render_template('roothome.html')

@app.route('/hashing')
def hashing_page():
    return render_template('hashing.html')

@app.route('/symmetric')
def symmetric_page():
    return render_template('symmetric.html')

@app.route('/asymmetric')
def asymmetric_page():
    return render_template('asymmetric.html')

@app.route("/algorithms")
def algorithms_page():
    return render_template("algorithms.html")

# ---------- HASHING ----------
@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    algorithm = request.form['algorithm']
    mode = request.form['mode']
    
    try:
        if mode == 'Text':
            data = request.form['text'].encode()
        elif mode == 'File':
            file = request.files['file']
            data = file.read()
        else:
            return jsonify({'error': 'Invalid mode selected'}), 400

        # Select hash algorithm
        if algorithm == 'MD5':
            hash_obj = hashlib.md5(data)
        elif algorithm == 'SHA-1':
            hash_obj = hashlib.sha1(data)
        elif algorithm == 'SHA-256':
            hash_obj = hashlib.sha256(data)
        elif algorithm == 'SHA3-256':
            hash_obj = hashlib.sha3_256(data)
        elif algorithm == 'SHA-512':
            hash_obj = hashlib.sha512(data)
        elif algorithm == 'SHA3-512':
            hash_obj = hashlib.sha3_512(data)
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        return jsonify({'hash': hash_obj.hexdigest()})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- SYMMETRIC ----------
@app.route('/symmetric_process', methods=['POST'])
def symmetric_process():
    try:
        algorithm = request.form['algorithm'].strip()
        action = request.form['action'].strip()
        key = request.form['key'].strip()
        text = request.form['text']

        cipher_map = {
            'AES': (AES, 16),
            'DES': (DES, 8),
            'Blowfish': (Blowfish, 8)
        }

        cipher_class, block_size = cipher_map.get(algorithm, (None, None))
        if not cipher_class:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        key_bytes = key.encode().ljust(block_size, b'0')[:block_size]
        iv = hashlib.sha256(key_bytes).digest()[:block_size]

        if action == 'Encrypt':
            cipher = cipher_class.new(key_bytes, cipher_class.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(text.encode(), block_size))
            return jsonify({'result': base64.b64encode(iv + ct_bytes).decode()})

        elif action == 'Decrypt':
            raw = base64.b64decode(text)
            cipher = cipher_class.new(key_bytes, cipher_class.MODE_CBC, raw[:block_size])
            decrypted = unpad(cipher.decrypt(raw[block_size:]), block_size)
            return jsonify({'result': decrypted.decode()})

        return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- ASYMMETRIC ----------
@app.route('/asymmetric_generate_keys', methods=['POST'])
def asymmetric_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return jsonify({'public_key': public_key, 'private_key': private_key})
@app.route('/asymmetric_encrypt', methods=['POST'])
def asymmetric_encrypt():
    data = request.get_json()
    try:
        public_key = RSA.import_key(data['public_key'])
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(data['message'].encode())
        return jsonify({'encrypted': base64.b64encode(encrypted).decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
@app.route('/asymmetric_decrypt', methods=['POST'])
def asymmetric_decrypt():
    encrypted = request.form['encrypted']
    private_key = request.form['private_key']
    try:
        private_key_obj = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key_obj)
        decrypted = cipher.decrypt(base64.b64decode(encrypted))
        return jsonify({'decrypted': decrypted.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ---------- DIFFIE-HELLMAN ----------
@app.route('/diffie_hellman', methods=['POST'])
def diffie_hellman():
    try:
        p = int(request.form['p'])
        g = int(request.form['g'])
        a = request.form.get('a')
        b = request.form.get('b')

        a = int(a) if a else secrets.randbelow(p)
        b = int(b) if b else secrets.randbelow(p)

        A = pow(g, a, p)
        B = pow(g, b, p)
        shared_a = pow(B, a, p)
        shared_b = pow(A, b, p)

        return jsonify({
            'alice_private_key': str(a),
            'bob_private_key': str(b),
            'alice_public_key': str(A),
            'bob_public_key': str(B),
            'alice_shared_secret': str(shared_a),
            'bob_shared_secret': str(shared_b)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ---------- FERNET ENCRYPTION USING SHARED SECRET ----------
SHARED_SECRET_KEY = hashlib.sha256(b'dh_shared_secret').digest()[:16]

@app.route('/api/encrypt_shared', methods=['POST'])
def encrypt_shared():
    try:
        text = request.json['text']
        iv = get_random_bytes(16)
        cipher = AES.new(SHARED_SECRET_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(text.encode(), 16))
        return jsonify({'encrypted': base64.b64encode(iv + encrypted).decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/decrypt_shared', methods=['POST'])
def decrypt_shared():
    try:
        encrypted = base64.b64decode(request.json['encrypted'])
        iv = encrypted[:16]
        cipher = AES.new(SHARED_SECRET_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted[16:]), 16)
        return jsonify({'decrypted': decrypted.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
