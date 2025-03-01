# 📂 Introducing: Smart File Management Web App!

## 📌 Project Overview

This is a **Flask-based File Management System** that allows users to **upload, manage, organize, and encrypt files** with **MongoDB as the backend** for storing user details and file metadata.

### 🚀 Features

- **User Authentication** (Admin & User Roles)
- **Secure File Uploads & Storage**
- **User-Specific File Management** (Users can only access their own files)
- **Admin Panel for Managing Users & Files**
- **File Organization (Sorting into Categories)**
- **File Encryption & Decryption**
- **Cloud Storage Integration (AWS S3 Optional)**
- **Version Control for Files**
- **AI-based File Categorization (OCR & NLP)**

---

## ⚙️ Tech Stack

- **Frontend:** Flask (Jinja Templates, HTML, CSS)
- **Backend:** Flask (Python)
- **Database:** MongoDB (via pymongo)
- **Cloud Storage (Optional):** AWS S3
- **Security:** JWT Authentication, Cryptography

---

## 📥 Installation & Setup

### 1️⃣ **Clone the Repository**

```bash
git clone https://github.com/yourusername/flask-file-management.git
cd flask-file-management
```

### 2️⃣ **Install Dependencies**

```bash
pip install -r requirements.txt
```

### 3️⃣ **Start MongoDB Server** (Ensure MongoDB is running locally)

```bash
mongod --dbpath C:/data/db
```

If using **MongoDB Atlas**, update `MONGO_URI` in `app.py`:

```python
MONGO_URI = "mongodb+srv://<username>:<password>@cluster.mongodb.net/file_management"
```

### 4️⃣ **Run Flask App**

```bash
python app.py
```

App will be available at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔑 User Authentication

- **Admin Credentials** (Create manually in MongoDB if not created automatically)

```bash
username: admin
password: admin123
```

- **User Registration & Login:** Users can register and log in via the web UI.
- **Role-Based Access:**
  - Admins can **view all files, manage users, and delete any file**.
  - Users can **only view, upload, and manage their own files**.

---

## 📂 File Management

### ✅ Uploading Files

- Users can upload files to the system.
- File metadata (name, path, uploader, timestamp) is stored in MongoDB.

### ✅ Listing Files

- **Admins see all files**.
- **Users only see their own files**.

### ✅ Deleting Files

- **Admins can delete any file**.
- **Users can only delete their own files**.

### ✅ Organizing Files

- Files are categorized automatically into `Documents`, `Images`, `Videos`, etc.

### ✅ Encryption & Decryption

- Users can encrypt/decrypt files using **AES encryption**.

### ✅ AI-Based Features

- **OCR for image-based text extraction**.
- **NLP-based categorization of text files**.

---

## 📊 Database Structure

### `users` Collection

| Field    | Type   | Description       |
| -------- | ------ | ----------------- |
| username | String | Unique username   |
| password | String | Hashed password   |
| role     | String | 'admin' or 'user' |

### `files` Collection

| Field        | Type      | Description        |
| ------------ | --------- | ------------------ |
| file\_name   | String    | Name of the file   |
| file\_path   | String    | Local path of file |
| uploaded\_by | String    | User who uploaded  |
| timestamp    | Timestamp | Upload time        |

---

## 🔥 API Endpoints

| Method   | Endpoint      | Description       |
| -------- | ------------- | ----------------- |
| **GET**  | `/`           | Home Page         |
| **POST** | `/login`      | User Login        |
| **POST** | `/register`   | User Registration |
| **GET**  | `/list_files` | List user files   |
| **POST** | `/upload`     | Upload a file     |
| **POST** | `/delete`     | Delete a file     |

---

## 🛠️ Future Improvements

- ✅ Full cloud storage support (AWS, Google Drive, Dropbox)
- ✅ Improved AI-based search functionality
- ✅ Web-based file preview

---

## 🤝 Contributing

Feel free to fork this project and submit pull requests!

---




