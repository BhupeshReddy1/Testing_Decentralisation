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
                        encrypted_hash TEXT NOT NULL,
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

def get_uploaded_files(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT file_name, encrypted_hash FROM user_files WHERE user_id = ?', [user_id])
    results = cursor.fetchall()
    uploaded_files = [{'filename': row[0], 'encrypted_hash': row[1]} for row in results]
    return uploaded_files

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


# Function to save file details to the database
def save_file_to_database(user_id, file_name, encrypted_hash):
    db = get_db()
    db.execute('INSERT INTO user_files (user_id, file_name, encrypted_hash) VALUES (?, ?, ?)', [user_id, file_name, encrypted_hash])
    db.commit()


def is_base64_encoded(s):
    try:
        # Attempt to decode the string
        b64decode(s)
        return True
    except binascii.Error:
        return False



# Function to retrieve encrypted hashes from the database
def get_user_encrypted_hashes(user_id):
    results = query_db('SELECT encrypted_hash FROM user_files WHERE user_id = ?', [user_id])
    return [result[0] for result in results]


# Function to save file details to the database


@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/index')
def index():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    user_id = session['user_id']
    shared_files = query_db('SELECT file_name, encrypted_hash FROM user_files WHERE user_id = ?', [user_id])

    return render_template('index.html', user_id=user_id, shared_files=shared_files)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        filename = request.form['filename']
        key = request.form['key']

        if file and filename and key:
            file_content = file.read()
            ipfs_hash = upload_to_ipfs(file_content)

            if ipfs_hash:
                encrypted_hash = encrypt_ipfs_hash(ipfs_hash, key)
                save_file_to_database(session['user_id'], filename, encrypted_hash)
                flash('File uploaded to IPFS successfully', 'success')
            else:
                flash('Failed to upload the file to IPFS', 'error')

            return redirect(url_for('upload'))

        else:
            flash('Please select a file, provide a filename, and enter a key.', 'error')
    uploaded_files = get_uploaded_files(session['user_id'])
    return render_template('upload.html',uploaded_files=uploaded_files)


@app.route('/decrypt', methods=['GET'])
def show_decrypt_form():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    return render_template('decrypt.html')


@app.route('/decrypt', methods=['POST'])
def decrypt():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    encrypted_hash = request.form['encrypted_hash']
    key = request.form['key']
    key_bytes = key.encode('utf-8')
    print(encrypted_hash)
    print(key)
    if not encrypted_hash or not key:
        flash('Encrypted hash or key missing.', 'error')
        return redirect(url_for('show_decrypt_form'))

    try:
        decrypted_hash = decrypt_ipfs_hash(encrypted_hash[1:-1], key_bytes)
        flash('Decryption successful', 'success')
        return render_template('decryption_result.html', decrypted_hash=decrypted_hash)
    except Exception as e:
        print('An error occurred during decryption: {}'.format(str(e)), 'error')
        return redirect(url_for('show_decrypt_form'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        # Retrieve user information from the database
        user_id = session['user_id']
        print(f"User ID: {user_id}")

        user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
        print(f"User: {user}")

        # Check if the current password matches the one in the database
        if user and user[2] == current_password:
            # Check if the new password and confirm new password match
            if new_password == confirm_new_password:
                # Update the user's password in the database
                db = get_db()
                db.execute('UPDATE users SET password = ? WHERE id = ?', [new_password, user_id])
                db.commit()
                flash('Password changed successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('New password and confirm new password do not match.', 'error')
        else:
            flash('Current password is incorrect.', 'error')

    return render_template('change_password.html')


@app.route('/share', methods=['GET', 'POST'])
def share():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        filename = request.form['filename']
        username = request.form['username']
        encrypting=request.form['encryption_hash']
        # Query the database to find the file with the matching filename
        file_entry = query_db('SELECT * FROM user_files WHERE file_name = ?', [filename], one=True)

        if file_entry:
            # Extract the encrypted hash from the retrieved tuple
            encrypted_hash = file_entry[3]  # Assuming the encrypted hash is at index 3
            user_id = query_db('SELECT id FROM users WHERE username = ?', [username], one=True)

            # Check if the user exists
            if user_id:
                try:
                    db = get_db()
                    # Insert the new file entry with the user_id
                    db.execute('INSERT INTO user_files (user_id, file_name, encrypted_hash) VALUES (?, ?, ?)',
                               [user_id[0], filename, encrypted_hash])
                    db.commit()
                    flash('File shared successfully.', 'success')
                    return redirect(url_for('index'))
                except Exception as e:
                    flash(f'An error occurred while sharing the file: {str(e)}', 'error')
                    return redirect(url_for('index'))
            else:
                flash('User does not exist.', 'error')
                return redirect(url_for('index'))

        else:
            flash('File not found in the database.', 'error')
            return redirect(url_for('index'))

    return render_template('share.html')


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
