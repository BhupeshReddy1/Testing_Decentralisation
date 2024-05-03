from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, g
from flask_socketio import SocketIO, emit
import sqlite3
import os
import json
import binascii
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib
from time import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
# Replace with a strong secret key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'ipfs_users.db'
socketio = SocketIO(app)


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
                user_id INTEGER,
                username TEXT not NULL,
                file_name TEXT NOT NULL,
                encrypted_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                file_name TEXT NOT NULL,
                encrypted_hash TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
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
# Define a list of admin usernames
admin_usernames = ['admin', 'mod1', 'mod2']
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


def encrypt_ipfs_hash(ipfs_hash, key):
    key_bytes = key.encode('utf-8')  # Encode key to bytes
    cipher = AES.new(key_bytes, AES.MODE_EAX)
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
def save_file_to_database(user_id, username, file_name, encrypted_hash):
    db = get_db()
    db.execute('INSERT INTO pending_uploads (user_id, username, file_name, encrypted_hash) VALUES (?, ?, ?, ?)',
               [user_id, username, file_name, encrypted_hash])
    db.commit()


# Function to retrieve encrypted hashes from the database
def get_user_encrypted_hashes(user_id):
    results = query_db('SELECT encrypted_hash FROM user_files WHERE user_id = ?', [user_id])
    return [result[0] for result in results]


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = int(timestamp)  # Convert timestamp to integer
        self.data = data.decode('utf-8') if isinstance(data, bytes) else data  # Decode bytes to string if necessary
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates SHA-256 hash of the block."""
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()



# Define Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the initial block (genesis block)."""
        timestamp = time()
        data = "Genesis Block"
        previous_hash = "0"
        self.chain.append(Block(0, timestamp, data, previous_hash))

    def get_latest_block(self):
        return self.chain[-1]

    def add_hash_as_block(self, data):
        """Adds a new block to the chain with the provided hash value."""
        previous_block = self.get_latest_block()
        previous_hash = previous_block.hash
        new_block = Block(len(self.chain), time(), data, previous_hash)
        self.chain.append(new_block)


# Initialize Blockchain object
blockchain = Blockchain()


def add_data_to_blockchain(data):
    # Convert bytes data to string
    data_str = data
    blockchain.add_hash_as_block(data_str)
    # Emit a socket message for real-time updates
    socketio.emit('new_block', json.dumps(blockchain.chain[-1].__dict__))


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


# Route to display blocks
@app.route('/blocks')
def display_blocks():
    return render_template('blocks.html', blockchain=blockchain)


# Route for adding a hash
@app.route('/add_hash', methods=['POST'])
def add_hash():
    # Retrieve hash from the form
    hash_value = request.form['hash']
    # Add hash to the blockchain
    blockchain.add_hash_as_block(hash_value)
    return redirect(url_for('display_blocks'))


# SocketIO connection event
@socketio.on('connect')
def handle_connect():
    emit('chain_updated', json.dumps([block.__dict__ for block in blockchain.chain]))


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
                save_file_to_database(session['user_id'], session['username'], filename, encrypted_hash)
                flash('File upload request submitted for approval.', 'success')
            else:
                flash('Failed to upload the file to IPFS', 'error')

            return redirect(url_for('upload'))

        else:
            flash('Please select a file, provide a filename, and enter a key.', 'error')

    # Fetch uploaded files based on the current user's user_id
    uploaded_files = get_uploaded_files(session['user_id'])
    print(uploaded_files)
    return render_template('upload.html', uploaded_files=uploaded_files)


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in') or session.get('role') not in admin_usernames:
        flash('Access denied. You must be logged in as an admin.', 'error')
        return redirect(url_for('login'))

    # Query pending uploads from the database
    pending_uploads = query_db('username, file_name, encrypted_hash FROM pending_uploads')

    return render_template('admin_dashboard.html', pending_uploads=pending_uploads)


@app.route('/decrypt', methods=['GET'])
def show_decrypt_form():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    return render_template('decrypt.html')


@app.route('/pending_uploads')
def pending_uploads():
    if not session.get('logged_in') or session['username'] not in admin_usernames:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    # Call the function to fetch pending uploads data
    pending_files = query_db('SELECT id, username, file_name, encrypted_hash FROM pending_uploads')

    pending_files_list = [{'id': row[0], 'username': row[1], 'file_name': row[2], 'encrypted_hash': row[3]} for row in pending_files]
    return render_template('pending_uploads.html', pending_files=pending_files_list)


@app.route('/approve_upload/<int:upload_id>', methods=['POST'])
def approve_upload(upload_id):
    if not session.get('logged_in') or session['username'] not in admin_usernames:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    db.execute('UPDATE pending_uploads SET status = ? WHERE id = ?', ['approved', upload_id])
    # Assuming db is your database connection object
    # Retrieve file information from pending_uploads
    file_info = db.execute('SELECT * FROM pending_uploads WHERE id = ?', (upload_id,)).fetchone()
    print(file_info)
    # Insert into user_files table
    db.execute('INSERT INTO user_files (user_id, username, file_name, encrypted_hash) VALUES (?, ?, ?, ?)',
               (file_info[1], file_info[2], file_info[3], file_info[4]))
    db.commit()
    #add to blockchain
    add_data_to_blockchain(file_info[4])
    # Delete from pending_uploads table
    db.execute('DELETE FROM pending_uploads WHERE id = ?', (upload_id,))
    db.commit()
    flash('Upload approved successfully.', 'success')
    return redirect(url_for('pending_uploads'))


@app.route('/reject_upload/<int:upload_id>', methods=['POST'])
def reject_upload(upload_id):
    if not session.get('logged_in') or session['username'] != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    db.execute('UPDATE pending_uploads SET status = ? WHERE id = ?', ['rejected', upload_id])
    db.execute('DELETE FROM pending_uploads WHERE id = ?', (upload_id,))
    db.commit()
    flash('Upload rejected.', 'success')
    return redirect(url_for('pending_uploads'))


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
        sender_username = session.get('username')  # Get the sender's username from the session
        filename = request.form['filename']
        receiver_username = request.form['username']
        # Assuming the encrypted hash is generated elsewhere and passed in the form
        encrypted_hash = request.form['encrypted_hash']

        if filename and receiver_username and encrypted_hash:
            # Query the database to find the receiver's user_id
            receiver_user = query_db('SELECT id FROM users WHERE username = ?', [receiver_username], one=True)

            if receiver_user:
                try:
                    db = get_db()
                    # Insert the shared hash into pending_uploads table
                    db.execute('INSERT INTO pending_uploads (user_id, username, file_name, encrypted_hash) VALUES (?, ?, ?, ?)',
                               [receiver_user[0], receiver_username, filename, encrypted_hash])
                    db.commit()
                    flash('File share request submitted for approval.', 'success')
                except Exception as e:
                    flash(f'An error occurred while sharing the file: {str(e)}', 'error')
            else:
                flash('Receiver username not found.', 'error')
        else:
            flash('Please provide all required information.', 'error')

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
            user_id = user[0]
            session['logged_in'] = True
            session['user_id'] = user_id
            session['username'] = username  # Set the username in the session
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
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
