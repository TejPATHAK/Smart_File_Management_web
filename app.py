from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, time, jwt, logging, shutil, boto3, zipfile, schedule, time as t, re
from collections import Counter
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
from botocore.exceptions import NoCredentialsError
from rapidfuzz import process, fuzz
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
from PIL import Image
import spacy

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = "your_flask_secret_key"  # Replace with a secure secret key
scheduler = BackgroundScheduler()
scheduler.start()
# Load NLP model
nlp = spacy.load("en_core_web_sm")

# AWS S3 Configuration
AWS_ACCESS_KEY = "your-access-key"
AWS_SECRET_KEY = "your-secret-key"
S3_BUCKET_NAME = "your-bucket-name"

# Initialize S3 client
s3_client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)



# --- Logging Setup ---
logging.basicConfig(filename='file_management.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication Setup ---
AUTH_SECRET = "mysecretkey"  # Secret for JWT encoding/decoding
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "user123", "role": "user"}
}

def authenticate(username, password):
    if username in users and users[username]["password"] == password:
        payload = {
            "username": username,
            "role": users[username]["role"],
            "iat": int(time.time())
        }
        token = jwt.encode(payload, AUTH_SECRET, algorithm="HS256")
        return token, payload
    return None, None

def require_admin():
    if "role" not in session or session["role"] != "admin":
        flash("Permission denied: Only admins can perform this action.", "error")
        logging.warning(f"User {session.get('username')} attempted admin-only action.")
        return False
    return True

# --- Key Management ---
def load_key(key_file="key.key"):
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        logging.info(f"Encryption key generated and saved to '{key_file}'")
    else:
        with open(key_file, "rb") as f:
            key = f.read()
        logging.info(f"Encryption key loaded from '{key_file}'")
    return key

ENCRYPTION_KEY = load_key()
cipher = Fernet(ENCRYPTION_KEY)

# --- S3 Client ---
s3 = boto3.client('s3')

# --- Helper Functions (CLI Operations Adapted for Web) ---
def list_files_op(directory):
    try:
        return os.listdir(directory)
    except Exception as e:
        logging.error(f"Error listing files in '{directory}': {e}")
        return []

def rename_file_op(directory, old_name, new_name):
    files = os.listdir(directory)
    match = process.extractOne(old_name, files)
    if match:
        old_path = os.path.join(directory, match[0])
        new_path = os.path.join(directory, new_name)
        os.rename(old_path, new_path)
        return True, f"File renamed from '{match[0]}' to '{new_name}'."
    return False, f"Error: File '{old_name}' not found."

def delete_path_op(directory, name):
    files = os.listdir(directory)
    match = process.extractOne(name, files)
    if match:
        path = os.path.join(directory, match[0])
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        return True, f"'{match[0]}' deleted successfully."
    return False, f"Error: No matching file/directory found for '{name}'."

def create_directory_op(directory, folder_name):
    path = os.path.join(directory, folder_name)
    os.makedirs(path, exist_ok=True)
    return f"Directory '{folder_name}' created successfully."

def upload_file_to_s3_op(directory, file_name, s3_file_name, bucket_name):
    local_file_path = os.path.join(directory, file_name)
    if os.path.exists(local_file_path):
        try:
            s3.upload_file(local_file_path, bucket_name, s3_file_name)
            return True, f"File '{local_file_path}' uploaded to S3 bucket '{bucket_name}' as '{s3_file_name}'."
        except Exception as e:
            return False, str(e)
    return False, f"Error: File '{file_name}' not found."

def compress_file_op(directory, file_name):
    file_path = os.path.join(directory, file_name)
    zip_file_path = os.path.join(directory, f"{file_name}.zip")
    if os.path.exists(file_path):
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(file_path, arcname=file_name)
        return True, f"File '{file_name}' compressed into '{zip_file_path}'."
    return False, f"Error: File '{file_name}' not found."

def encrypt_file_op(directory, file_name):
    file_path = os.path.join(directory, file_name)
    encrypted_file_path = os.path.join(directory, f"{file_name}.enc")
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = cipher.encrypt(file_data)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        return True, f"File '{file_name}' encrypted as '{encrypted_file_path}'."
    return False, f"Error: File '{file_name}' not found."

def decrypt_file_op(directory, encrypted_file_name):
    key_file = "key.key"
    encrypted_file_path = os.path.join(directory, encrypted_file_name)
    try:
        with open(key_file, "rb") as keyfile:
            key = keyfile.read()
    except Exception as e:
        return False, "Error: Encryption key file not found!"
    cipher_local = Fernet(key)
    try:
        with open(encrypted_file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()
        decrypted_data = cipher_local.decrypt(encrypted_data)
        decrypted_file_path = encrypted_file_path.replace(".enc", "")
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)
        return True, f"File decrypted and saved as '{decrypted_file_path}'."
    except Exception as e:
        return False, f"Decryption error: {e}"

def organize_files_op(directory):
    categories = {
        "Documents": ['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx', 'odt'],
        "Images": ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg'],
        "Videos": ['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv'],
        "Music": ['mp3', 'wav', 'flac', 'aac', 'ogg'],
        "Archives": ['zip', 'rar', '7z', 'tar', 'gz']
    }
    results = []
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            ext = file.split('.')[-1].lower() if '.' in file else ""
            moved = False
            for category, ext_list in categories.items():
                if ext in ext_list:
                    target_folder = os.path.join(directory, category)
                    if not os.path.exists(target_folder):
                        os.makedirs(target_folder)
                    shutil.move(file_path, os.path.join(target_folder, file))
                    results.append(f"Moved '{file}' to '{target_folder}'.")
                    moved = True
                    break
            if not moved:
                target_folder = os.path.join(directory, "Others")
                if not os.path.exists(target_folder):
                    os.makedirs(target_folder)
                shutil.move(file_path, os.path.join(target_folder, file))
                results.append(f"Moved '{file}' to '{target_folder}'.")
    return results

def save_version_op(directory, file_name):
    file_path = os.path.join(directory, file_name)
    if not os.path.exists(file_path):
        return False, f"Error: File '{file_name}' not found!"
    versions_dir = os.path.join(directory, "versions")
    if not os.path.exists(versions_dir):
        os.makedirs(versions_dir)
    base, ext = os.path.splitext(file_name)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    versioned_file_name = f"{base}_{timestamp}{ext}"
    versioned_file_path = os.path.join(versions_dir, versioned_file_name)
    shutil.copy2(file_path, versioned_file_path)
    return True, f"Version saved as '{versioned_file_name}'."

def list_versions_op(directory, file_name):
    versions_dir = os.path.join(directory, "versions")
    if not os.path.exists(versions_dir):
        return []
    base, ext = os.path.splitext(file_name)
    versions = [f for f in os.listdir(versions_dir) if f.startswith(f"{base}_") and f.endswith(ext)]
    return sorted(versions)

# --- AI-POWERED FUNCTIONS ---
def suggest_folder_from_text(text):
    stopwords = set(["the", "and", "is", "in", "to", "of", "a", "for", "with", "on", "that", "this", "it", "as", "by", "an"])
    words = re.findall(r'\w+', text.lower())
    words = [word for word in words if word not in stopwords and len(word) > 3]
    if not words:
        return "Uncategorized"
    counter = Counter(words)
    most_common = counter.most_common(3)
    suggested = "_".join([w for w, count in most_common])
    return suggested

def ai_assistant_suggest_folder(directory, file_name):
    file_path = os.path.join(directory, file_name)
    ext = file_name.split('.')[-1].lower()
    text = ""
    if ext in ["jpg", "jpeg", "png", "tiff", "bmp", "gif"]:
        try:
            text = pytesseract.image_to_string(Image.open(file_path))
        except Exception as e:
            return None, f"Error during OCR: {e}"
    elif ext in ["txt"]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            return None, f"Error reading text file: {e}"
    else:
        return None, "Unsupported file type for AI categorization. Only images and text files are supported."
    if text:
        suggested = suggest_folder_from_text(text)
        return suggested, f"Extracted text: {text}"
    else:
        return None, "No text could be extracted."

# --- Flask Routes ---
@app.route('/')
def dashboard():
    if "username" not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session["username"], role=session["role"])

@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login_route():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        token, payload = authenticate(username, password)
        if token:
            session['auth_token'] = token
            session['username'] = username
            session['role'] = payload.get("role")
            logging.info(f"User {username} logged in successfully.")
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            logging.error(f"Failed login attempt for user {username}.")
            flash("Invalid credentials.", "error")
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout_route():
    user = session.get("username", "Unknown")
    session.clear()
    logging.info(f"User {user} logged out.")
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/list_files', methods=['GET'])
def list_files_route():
    if "username" not in session:
        return redirect(url_for('login'))
    directory = request.args.get("directory", ".")
    try:
        files = os.listdir(directory)
        logging.info(f"User {session['username']} listed files in directory '{directory}'.")
    except Exception as e:
        files = []
        flash(f"Error: {e}", "error")
        logging.error(f"Error listing files in directory '{directory}': {e}")
    return render_template('list_files.html', files=files, directory=directory)

@app.route('/list_files', methods=['GET', 'POST'])
def list_files():
    files = None
    if request.method == 'POST':
        directory = request.form['directory']
        
        if not os.path.exists(directory):
            return render_template('list_files.html', files=[], message="Directory does not exist!")

        files = os.listdir(directory)

    return render_template('list_files.html', files=files)

@app.route('/rename', methods=['GET', 'POST'])
def rename_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        if not require_admin():
            return redirect(url_for('dashboard'))
        directory = request.form.get("directory")
        old_name = request.form.get("old_name")
        new_name = request.form.get("new_name")
        success, msg = rename_file_op(directory, old_name, new_name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('rename.html')

@app.route('/rename_file', methods=['GET', 'POST'])
def rename_file():
    message = None
    if request.method == 'POST':
        directory = request.form['directory']
        old_name = request.form['old_name']
        new_name = request.form['new_name']

        old_path = os.path.join(directory, old_name)
        new_path = os.path.join(directory, new_name)

        if os.path.exists(old_path):
            os.rename(old_path, new_path)
            message = f"File '{old_name}' renamed to '{new_name}' successfully!"
        else:
            message = "File does not exist!"

    return render_template('rename.html', message=message)

@app.route('/delete', methods=['GET', 'POST'])
def delete_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        if not require_admin():
            return redirect(url_for('dashboard'))
        directory = request.form.get("directory")
        name = request.form.get("name")
        success, msg = delete_path_op(directory, name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('delete.html')


@app.route('/delete', methods=['GET', 'POST'])
def delete_path():
    if request.method == 'POST':
        directory = request.form['directory']
        name = request.form['name']
        path = os.path.join(directory, name)

        if os.path.isfile(path):
            os.remove(path)
            message = "File deleted successfully!"
        elif os.path.isdir(path):
            shutil.rmtree(path)
            message = "Directory deleted successfully!"
        else:
            message = "The specified path does not exist."

        return render_template('delete.html', message=message)

    return render_template('delete.html')



@app.route('/create_directory', methods=['GET', 'POST'])
def create_directory_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        folder_name = request.form.get("folder_name")
        msg = create_directory_op(directory, folder_name)
        flash(msg, "success")
        return redirect(url_for('dashboard'))
    return render_template('create_directory.html')


@app.route('/create_directory', methods=['GET', 'POST'])
def create_directory():
    message = None
    if request.method == 'POST':
        directory = request.form['directory']
        folder_name = request.form['folder_name']
        path = os.path.join(directory, folder_name)

        try:
            os.makedirs(path, exist_ok=True)
            message = f"Directory '{folder_name}' created successfully at '{directory}'!"
        except Exception as e:
            message = f"Error: {str(e)}"

    return render_template('create_directory.html', message=message)

@app.route('/upload', methods=['GET', 'POST'])
def upload_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        file_name = request.form.get("file_name")
        s3_file_name = request.form.get("s3_file_name")
        bucket_name = request.form.get("bucket_name")
        success, msg = upload_file_to_s3_op(directory, file_name, s3_file_name, bucket_name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('upload.html')


@app.route('/upload')
def upload():
    return render_template('upload.html')

# Route to handle file upload
@app.route('/upload_s3', methods=['POST'])
def upload_s3():
    if 'file' not in request.files:
        return render_template("upload.html", message="No file uploaded!")

    file = request.files['file']
    if file.filename == '':
        return render_template("upload.html", message="No selected file!")

    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, file.filename)
        file_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{file.filename}"
        return render_template("upload.html", message=f"File uploaded successfully! URL: {file_url}")
    except Exception as e:
        return render_template("upload.html", message=f"Upload failed: {str(e)}")

@app.route('/search', methods=['GET', 'POST'])
def search_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        search_term = request.form.get("search_term")
        filter_type = request.form.get("filter_type")
        fuzzy = request.form.get("fuzzy") == "yes"
        # Simplified search logic
        files = os.listdir(directory)
        matched_files = []
        for file in files:
            file_extension = file.split('.')[-1] if '.' in file else ''
            if filter_type == "name":
                if fuzzy:
                    if fuzz.partial_ratio(search_term.lower(), file.lower()) > 80:
                        matched_files.append(file)
                else:
                    if search_term.lower() in file.lower():
                        matched_files.append(file)
            elif filter_type == "type":
                if search_term.lower().lstrip('.') == file_extension.lower():
                    matched_files.append(file)
            elif filter_type == "size":
                try:
                    search_size = int(search_term)
                    if os.path.getsize(os.path.join(directory, file)) >= search_size:
                        matched_files.append(file)
                except:
                    pass
            elif filter_type == "date":
                if search_term.lower() in time.ctime(os.path.getmtime(os.path.join(directory, file))).lower():
                    matched_files.append(file)
        return render_template('search_results.html', files=matched_files, search_term=search_term)
    return render_template('search.html')


@app.route('/search', methods=['GET', 'POST'])
def search():
    search_results = None
    if request.method == 'POST':
        directory = request.form['directory']
        search_term = request.form['search_term']

        if not os.path.exists(directory):
            return render_template('search.html', search_results=[], message="Directory does not exist!")

        found_items = []
        for root, dirs, files in os.walk(directory):
            for name in dirs + files:
                if search_term.lower() in name.lower():  # Case-insensitive search
                    found_items.append(os.path.join(root, name))

        search_results = found_items

    return render_template('search.html', search_results=search_results)


@app.route('/compress', methods=['GET', 'POST'])
def compress_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        file_name = request.form.get("file_name")
        success, msg = compress_file_op(directory, file_name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('compress.html')


@app.route('/compress', methods=['GET', 'POST'])
def compress_path():
    if request.method == 'POST':
        directory = request.form['directory']
        name = request.form['name']
        zip_name = request.form['zip_name']
        path = os.path.join(directory, name)
        zip_path = os.path.join(directory, zip_name + ".zip")

        if os.path.exists(path):
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if os.path.isdir(path):
                    for foldername, subfolders, filenames in os.walk(path):
                        for filename in filenames:
                            file_path = os.path.join(foldername, filename)
                            zipf.write(file_path, os.path.relpath(file_path, directory))
                else:
                    zipf.write(path, os.path.basename(path))

            message = f"Successfully compressed to {zip_name}.zip"
        else:
            message = "The specified file or directory does not exist."

        return render_template('compress.html', message=message)

    return render_template('compress.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        file_name = request.form.get("file_name")
        success, msg = encrypt_file_op(directory, file_name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('encrypt.html')

from cryptography.fernet import Fernet
import os

# Generate a key (Save this key for decryption)
def generate_key(password: str):
    return Fernet(Fernet.generate_key())

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('encrypt.html', message="No file selected!")

        file = request.files['file']
        password = request.form['password']

        if file.filename == '':
            return render_template('encrypt.html', message="No file selected!")

        # Read file content
        file_content = file.read()

        # Generate an encryption key from password
        key = generate_key(password)
        cipher = Fernet(key._signing_key)  # Encrypt using the key

        # Encrypt file content
        encrypted_content = cipher.encrypt(file_content)

        # Save the encrypted file
        encrypted_file_path = os.path.join("encrypted_files", file.filename + ".enc")
        os.makedirs("encrypted_files", exist_ok=True)

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_content)

        return render_template('encrypt.html', message=f"File encrypted successfully! Saved as {file.filename}.enc")

    return render_template('encrypt.html')


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        encrypted_file_name = request.form.get("encrypted_file_name")
        success, msg = decrypt_file_op(directory, encrypted_file_name)
        if success:
            flash(msg, "success")
        else:
            flash(msg, "error")
        return redirect(url_for('dashboard'))
    return render_template('decrypt.html')
    

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('decrypt.html', message="No file selected!")

        file = request.files['file']
        password = request.form['password']

        if file.filename == '':
            return render_template('decrypt.html', message="No file selected!")

        try:
            # Read encrypted file content
            encrypted_content = file.read()

            # Generate decryption key
            key = generate_key(password)
            cipher = Fernet(key._signing_key)

            # Decrypt the content
            decrypted_content = cipher.decrypt(encrypted_content)

            # Save the decrypted file
            decrypted_file_path = os.path.join("decrypted_files", file.filename.replace(".enc", ""))
            os.makedirs("decrypted_files", exist_ok=True)

            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_content)

            return render_template('decrypt.html', message=f"File decrypted successfully! Saved as {file.filename.replace('.enc', '')}")

        except Exception as e:
            return render_template('decrypt.html', message="Error: Incorrect password or file is corrupted.")

    return render_template('decrypt.html')

@app.route('/organize', methods=['GET', 'POST'])
def organize_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        results = organize_files_op(directory)
        flash("Organization complete.", "success")
        return render_template('organize.html', results=results, directory=directory)
    return render_template('organize.html')

@app.route('/organize', methods=['GET', 'POST'])
def organize():
    if request.method == 'POST':
        directory = request.form['directory']

        if not os.path.exists(directory):
            return render_template('organize.html', message="Directory does not exist!")

        # Organizing files
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)

            if os.path.isfile(file_path):
                file_ext = os.path.splitext(file)[-1].lower()
                folder_name = None

                for category, extensions in FILE_CATEGORIES.items():
                    if file_ext in extensions:
                        folder_name = category
                        break

                if not folder_name:
                    folder_name = "Others"

                destination_folder = os.path.join(directory, folder_name)
                os.makedirs(destination_folder, exist_ok=True)
                shutil.move(file_path, os.path.join(destination_folder, file))

        return render_template('organize.html', message="Files organized successfully!")

    return render_template('organize.html')


@app.route('/schedule', methods=['GET', 'POST'])
def schedule_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        directory = request.form.get("directory")
        interval = request.form.get("interval")
        try:
            interval = int(interval)
        except ValueError:
            flash("Invalid interval, using default of 1 minute.", "error")
            interval = 1
        import threading
        threading.Thread(target=schedule_organization, args=(directory, interval)).start()
        flash(f"Scheduled organization every {interval} minute(s) in {directory}.", "success")
        return redirect(url_for('dashboard'))
    return render_template('schedule.html')

def execute_task(directory, task):
    if not os.path.exists(directory):
        return f"Directory {directory} does not exist!"

    if task == "delete":
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        return "Files deleted successfully!"

    elif task == "organize":
        FILE_CATEGORIES = {
            "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg"],
            "Documents": [".pdf", ".docx", ".doc", ".txt", ".xls", ".xlsx", ".ppt", ".pptx"],
            "Videos": [".mp4", ".avi", ".mov", ".mkv", ".flv"],
            "Audio": [".mp3", ".wav", ".aac", ".ogg"],
            "Others": []
        }
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                ext = os.path.splitext(file)[-1].lower()
                folder_name = next((key for key, val in FILE_CATEGORIES.items() if ext in val), "Others")
                dest_folder = os.path.join(directory, folder_name)
                os.makedirs(dest_folder, exist_ok=True)
                shutil.move(file_path, os.path.join(dest_folder, file))
        return "Files organized successfully!"

    elif task == "compress":
        zip_path = os.path.join(directory, "compressed_files.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path):
                    zipf.write(file_path, os.path.basename(file_path))
        return "Files compressed successfully!"

    elif task == "encrypt":
        key = Fernet.generate_key()
        cipher = Fernet(key)
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                with open(file_path, "rb") as f:
                    encrypted_data = cipher.encrypt(f.read())
                with open(file_path + ".enc", "wb") as f:
                    f.write(encrypted_data)
                os.remove(file_path)
        return "Files encrypted successfully!"

    elif task == "decrypt":
        key = Fernet.generate_key()  # Store this securely
        cipher = Fernet(key)
        for file in os.listdir(directory):
            if file.endswith(".enc"):
                file_path = os.path.join(directory, file)
                with open(file_path, "rb") as f:
                    decrypted_data = cipher.decrypt(f.read())
                original_file_path = os.path.join(directory, file.replace(".enc", ""))
                with open(original_file_path, "wb") as f:
                    f.write(decrypted_data)
                os.remove(file_path)
        return "Files decrypted successfully!"

@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if request.method == 'POST':
        directory = request.form['directory']
        interval = int(request.form.get('interval', 1))  # Default: 1 minute

        # Start the organization scheduler
        schedule_organization(directory, interval)

        return render_template('schedule.html', message=f"Auto-organization scheduled every {interval} minutes!")

    return render_template('schedule.html')


@app.route('/version_control', methods=['GET', 'POST'])
def version_control_route():
    if "username" not in session:
        return redirect(url_for('login'))
    # For simplicity, we render a version control page where further operations can be done.
    return render_template('version_control.html')


@app.route('/version_control', methods=['GET', 'POST'])
def version_control():
    versions = []
    file_path = None

    if request.method == 'POST':
        file_path = request.form.get('file_path')
        versions = get_file_versions(file_path)  # Function to fetch stored versions

    return render_template('version_control.html', versions=versions, file_path=file_path)


@app.route('/restore_version/<path:file_path>/<version_id>')
def restore_version(file_path, version_id):
    success = restore_file_version(file_path, version_id)  # Restore file function
    if success:
        flash("File restored successfully!", "success")
    else:
        flash("Failed to restore file.", "error")

    return redirect(url_for('version_control'))



VERSION_DIR = "file_versions"

def get_file_versions(file_path):
    """Retrieve all saved versions of a file"""
    version_folder = os.path.join(VERSION_DIR, os.path.basename(file_path))
    if not os.path.exists(version_folder):
        return []

    versions = []
    for file in sorted(os.listdir(version_folder), reverse=True):
        versions.append({
            "version_id": file,
            "timestamp": datetime.fromtimestamp(os.path.getmtime(os.path.join(version_folder, file)))
        })

    return versions

def restore_file_version(file_path, version_id):
    """Restore a specific version of the file"""
    version_folder = os.path.join(VERSION_DIR, os.path.basename(file_path))
    version_path = os.path.join(version_folder, version_id)

    if os.path.exists(version_path):
        shutil.copy(version_path, file_path)
        return True
    return False



@app.route('/ai', methods=['GET', 'POST'])
def ai_route():
    if "username" not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        action = request.form.get("action")
        directory = request.form.get("directory")
        file_name = request.form.get("file_name")
        if action == "ocr":
            try:
                text = pytesseract.image_to_string(Image.open(os.path.join(directory, file_name)))
                flash(f"OCR Result: {text}", "info")
            except Exception as e:
                flash(f"OCR error: {e}", "error")
        elif action == "suggest":
            suggestion, info = ai_assistant_suggest_folder(directory, file_name)
            if suggestion:
                flash(f"Suggested folder: {suggestion}", "info")
            else:
                flash(info, "error")
        return redirect(url_for('dashboard'))
    return render_template('ai.html')

# Route to display AI.html
@app.route('/ai')
def ai():
    return render_template('ai.html')

# OCR Feature: Extract Text from Image
@app.route('/extract_text', methods=['POST'])
def extract_text():
    if 'image_file' not in request.files:
        return "No file uploaded!"
    
    image_file = request.files['image_file']
    if image_file.filename == '':
        return "No selected file!"

    image = Image.open(image_file)
    extracted_text = pytesseract.image_to_string(image)
    
    return f"<h3>Extracted Text:</h3><p>{extracted_text}</p><a href='/ai'>Back</a>"

# NLP-Based File Categorization
@app.route('/categorize_file', methods=['POST'])
def categorize_file():
    if 'file' not in request.files:
        return "No file uploaded!"
    
    file = request.files['file']
    text = file.read().decode("utf-8")

    doc = nlp(text)
    categories = set()
    
    for ent in doc.ents:
        categories.add(ent.label_)
    
    return f"<h3>File Categorization:</h3><p>{', '.join(categories)}</p><a href='/ai'>Back</a>"

# AI-Powered Search
@app.route('/ai_search', methods=['POST'])
def ai_search():
    query = request.form['search_query']
    return f"<h3>Search Results for '{query}' (AI-based functionality coming soon!)</h3><a href='/ai'>Back</a>"



# --- MAIN MENU ROUTE ---
@app.route('/dashboard')
def dashboard_route():
    if "username" not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session["username"], role=session["role"])



if __name__ == '__main__':
    app.run(debug=True)
