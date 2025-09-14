from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3, os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

# Increase maximum file size and timeout for large videos
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB limit

DB_FILE = "users.db"
UPLOAD_FOLDER = "videos"
ALLOWED_EXTENSIONS = {"mp4", "mov", "avi", "mkv", "webm"}

# Create upload folder if not exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Initialize database (run once) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)
    
    # Check if admin accounts exist, if not create them
    cur.execute("SELECT COUNT(*) FROM users WHERE username IN ('admin1', 'admin2')")
    admin_count = cur.fetchone()[0]
    
    if admin_count < 2:
        # Insert 2 admins if they don't exist
        try:
            cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", 
                        ("admin1", "pass123", "admin"))
            cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", 
                        ("admin2", "pass123", "admin"))
            print("Admin accounts created successfully!")
        except sqlite3.IntegrityError:
            print("Admin accounts already exist or couldn't be created")
    
    # Check if we have at least 8 regular users
    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'user'")
    user_count = cur.fetchone()[0]
    
    if user_count < 8:
        # Insert users if we don't have enough
        for i in range(user_count + 1, 9):
            try:
                cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                            (f"user{i}", "pass123", "user"))
            except sqlite3.IntegrityError:
                print(f"User user{i} already exists")
    
    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users WHERE username=? AND password=?", (username, password))
    user = cur.fetchone()
    conn.close()
    return user

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = check_user(username, password)
        if user:
            session["username"] = user[0]
            session["role"] = user[1]
            return redirect(url_for("dashboard"))
        else:
            return "Invalid username or password"
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    # Handle video upload (admin only)
    if request.method == "POST" and session["role"] == "admin":
        if "video" not in request.files:
            return "No file selected"
        file = request.files["video"]
        if file.filename == "":
            return "No filename"
        if file and allowed_file(file.filename):
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            return redirect(url_for("dashboard"))

    # List all uploaded videos
    videos = os.listdir(UPLOAD_FOLDER)

    return render_template("dashboard.html", 
                           username=session["username"], 
                           role=session["role"], 
                           videos=videos)

@app.route("/video/<name>")
def video(name):
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("video.html", name=name)

@app.route("/videos/<filename>")
def serve_video(filename):
    # Use send_file with conditional requests for better performance
    response = send_from_directory(UPLOAD_FOLDER, filename)
    
    # Set appropriate headers for video streaming
    response.headers.add('Accept-Ranges', 'bytes')
    response.headers.add('Cache-Control', 'no-cache')
    
    return response

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/delete/<name>", methods=["POST"])
def delete_video(name):
    if "username" not in session:
        return redirect(url_for("login"))
    if session["role"] != "admin":
        return "Unauthorized action"

    filepath = os.path.join(UPLOAD_FOLDER, name)
    if os.path.exists(filepath):
        os.remove(filepath)
    return redirect(url_for("dashboard"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    message = ""
    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        # Verify old password
        cur.execute("SELECT password FROM users WHERE username=?", (session["username"],))
        result = cur.fetchone()
        
        if result:
            stored_password = result[0]
            if stored_password == old_password:
                cur.execute("UPDATE users SET password=? WHERE username=?", (new_password, session["username"]))
                conn.commit()
                message = "✅ Password updated successfully!"
            else:
                message = "❌ Old password is incorrect."
        else:
            message = "❌ User not found."

        conn.close()

    return render_template("change_password.html", username=session["username"], message=message)

@app.route("/manage_users", methods=["GET", "POST"])
def manage_users():
    if "username" not in session:
        return redirect(url_for("login"))
    if session["role"] != "admin":
        return "Unauthorized action"

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Handle Add User
    if request.method == "POST" and "add_user" in request.form:
        new_username = request.form["new_username"]
        new_password = request.form["new_password"]
        new_role = request.form["new_role"]
        try:
            cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (new_username, new_password, new_role))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists!"

    # Handle Update Password/Role
    if request.method == "POST" and "update_user" in request.form:
        user_id = request.form["user_id"]
        new_password = request.form["update_password"]
        new_role = request.form["update_role"]
        cur.execute("UPDATE users SET password=?, role=? WHERE id=?",
                    (new_password, new_role, user_id))
        conn.commit()

    # Handle Delete User
    if request.method == "POST" and "delete_user" in request.form:
        user_id = request.form["user_id"]
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()

    # Get updated users list
    cur.execute("SELECT id, username, password, role FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template("manage_users.html", users=users, username=session["username"])

# Initialize the database when the app starts
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)