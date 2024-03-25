from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, g
import sqlite3
import os
import binascii
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'ipfs_users.db'  # SQLite database file

# Function to initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''  
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        file_name TEXT NOT NULL,
                        ipfs_hash TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
        db.commit()

# Function to get a database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
    return db

# Function to query the database
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# Initialize the database
init_db()

# Replace with the IP address and port of your IPFS node
ipfs_api_url = "http://localhost:5001/api/v0"


# Function to upload a file to IPFS
def upload_to_ipfs(file_content):
    files = {'file': ('filename.txt', file_content)}
    response = requests.post(f"{ipfs_api_url}/add", files=files)

    if response.status_code == 200:
        ipfs_hash = response.json()['Hash']
        return ipfs_hash
    else:
        return None




# Encryption
def encrypt_ipfs_hash(ipfs_hash, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(ipfs_hash.encode())
    return b64encode(cipher.nonce + tag + ciphertext)


def is_base64_encoded(s):
    try:
        # Attempt to decode the string
        b64decode(s)
        return True
    except binascii.Error:
        return False

# Decryption
def decrypt_ipfs_hash(encrypted_hash, key):
    encrypted_data = b64decode(encrypted_hash)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


# Function to save encrypted hash in the database


# Function to retrieve encrypted hashes from the database
def get_user_encrypted_hashes(user_id):
    results = query_db('SELECT encrypted_hash FROM user_files WHERE user_id = ?', [user_id])
    return [result[0] for result in results]


"""# Function to remove encrypted hash from the database
def remove_user_file(user_id, encrypted_hash):
    db = get_db()
    cursor = db.cursor()  # Get a cursor for feedback
    print(f"Executing DELETE query with user_id: {user_id}, encrypted_hash: {encrypted_hash}")
    cursor.execute('DELETE FROM user_files WHERE user_id = ? AND encrypted_hash = ?', [user_id, encrypted_hash])
    rows_deleted = cursor.rowcount  # Check rows affected
    print(f"Rows deleted: {rows_deleted}")
    db.commit()"""

"""# Function to download a file from IPFS
def download_from_ipfs(ipfs_hash):
    print(f"Fetching IPFS content from: {ipfs_api_url}/cat/{ipfs_hash}")
    response = requests.get(f"{ipfs_api_url}/cat/{ipfs_hash}")
    if response.status_code == 200:
        file_content = response.content
        return file_content
    else:
        return None"""
# Function to save file details to the database
def save_file_to_db(user_id, file_name, ipfs_hash):
    db = get_db()
    db.execute('INSERT INTO user_files (user_id, file_name, ipfs_hash) VALUES (?, ?, ?)', [user_id, file_name, ipfs_hash])
    db.commit()

# Function to upload a file to IPFS
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/index')
def index():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    user_id = session['user_id']
    return render_template('index.html', user_id=user_id)

"""@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        filename = request.form['filename']
        if file and filename:
            file_content = file.read()
            ipfs_hash = upload_to_ipfs(file_content)
            if ipfs_hash:
                save_file_to_db(session['user_id'], filename, ipfs_hash)
                flash('File uploaded to IPFS successfully', 'success')
            else:
                flash('Failed to upload the file to IPFS', 'error')
            return redirect(url_for('upload'))
        else:
            flash('Please select a file and provide a filename.', 'error')
    return render_template('upload.html')"""

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        filename = request.form['filename']
        if file and filename:
            file_content = file.read()
            ipfs_hash = upload_to_ipfs(file_content)
            if ipfs_hash:
                save_file_to_db(session['user_id'], filename, ipfs_hash)
                flash('File uploaded to IPFS successfully', 'success')
            else:
                flash('Failed to upload the file to IPFS', 'error')
            return redirect(url_for('upload'))
        else:
            flash('Please select a file and provide a filename.', 'error')
    return render_template('upload.html')


"""@app.route('/download/<encrypted_hash>')
def download(encrypted_hash):
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_encrypted_hashes = get_user_encrypted_hashes(user_id)

    if encrypted_hash not in user_encrypted_hashes:
        flash('You do not have permission to download this file.', 'error')
        return redirect(url_for('index'))

    # Decrypt the encrypted hash to get the IPFS hash
    key = request.args.get('key', '')  # Assuming the key is provided as a query parameter
    decrypted_ipfs_hash = decrypt_ipfs_hash(encrypted_hash, key)

    if decrypted_ipfs_hash:
        downloaded_content = download_from_ipfs(decrypted_ipfs_hash)

        if downloaded_content:
            response = Response(downloaded_content, content_type='application/octet-stream')
            response.headers['Content-Disposition'] = f'attachment; filename={decrypted_ipfs_hash}.txt'
            return response
        else:
            flash('Failed to download the file from IPFS', 'error')
    else:
        flash('Failed to decrypt the IPFS hash', 'error')

    return redirect(url_for('index'))"""

"""
@app.route('/remove', methods=['POST'])
def remove():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    encrypted_hash = request.form.get('encrypted_hash', '')

    if not encrypted_hash:
        flash('Encrypted hash is required', 'error')
        return redirect(url_for('index'))
        # Remove the 'b' prefix from the encrypted hash if present
    if encrypted_hash.startswith("b'"):
        encrypted_hash = encrypted_hash[2:-1]
        print(encrypted_hash)
    encrypted_hash_bytes = encrypted_hash.encode('utf-8')
    print(f"Attempting to delete file with encrypted_hash: {encrypted_hash}")
    print(f"User ID: {user_id}")
    print(f"Current user encrypted hashes: {get_user_encrypted_hashes(user_id)}")

    remove_user_file(user_id, encrypted_hash_bytes)

    print(f"User encrypted hashes after removal: {get_user_encrypted_hashes(user_id)}")
    flash('File removed successfully', 'success')
    return redirect(url_for('index'), code=302)"""


"""@app.route('/decrypt', methods=['POST'])
def decrypt():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    encrypted_hash = request.form.get('encrypted_hash')
    key = request.form.get('key')
    key_bytes = key.encode('utf-8')
    if not encrypted_hash or not key:
        flash('Encrypted hash or key missing.', 'error')
        return redirect(url_for('index'))

    decrypted_hash = decrypt_ipfs_hash(encrypted_hash[1:], key_bytes)
    flash('Decryption successful', 'success')
    return render_template('decryption_result.html', decrypted_hash=decrypted_hash)"""


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if user:
            flash('Username already exists. Please choose another one.', 'error')
        else:
            db = get_db()
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, password])
            db.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], one=True)

        if user:
            user_id = user[0]  # Assuming user_id is the first column in the SELECT statement
            session['logged_in'] = True
            session['user_id'] = user_id  # Set the user ID in the session
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if session.get('logged_in'):
        session.pop('logged_in', None)
        session.pop('user_id', None)
        flash('Logout successful', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
