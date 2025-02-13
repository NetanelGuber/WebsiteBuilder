from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import json
import os
import bcrypt  # Secure password hashing
import bleach  # XSS Protection
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps  # Fixes decorator issue

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # Store in env variable
DATABASE = 'pages.db'

# Secure hashed password (set in environment variables)
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode())

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT CHECK(role IN ('admin', 'editor', 'viewer')) NOT NULL
            )
        ''')
        # Create the page_versions table for backups/versions
        conn.execute('''
            CREATE TABLE IF NOT EXISTS page_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                content TEXT,
                saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(page_id) REFERENCES pages(id)
            )
        ''')
        conn.commit()

init_db()

# User class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        return User(id=user['id'], username=user['username'], role=user['role'])
    return None

# Sanitize HTML before rendering
@app.template_filter('sanitize_html')
def sanitize_html(html):
    return bleach.clean(html, tags=['p', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li'], strip=True)

# Restrict access to certain roles
def role_required(*roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                flash("Access denied!", "danger")
                return redirect(url_for('index'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/')
def index():
    search_query = request.args.get('q', '')
    sort_by = request.args.get('sort', 'created_at')
    # Whitelist sorting fields to prevent SQL injection
    ALLOWED_SORT_FIELDS = ["created_at", "name"]
    if sort_by not in ALLOWED_SORT_FIELDS:
        sort_by = "created_at"

    with get_db_connection() as conn:
        if search_query:
            pages = conn.execute(
                f"SELECT * FROM pages WHERE name LIKE ? OR description LIKE ? ORDER BY {sort_by} DESC",
                ('%' + search_query + '%', '%' + search_query + '%')
            ).fetchall()
        else:
            pages = conn.execute(f"SELECT * FROM pages ORDER BY {sort_by} DESC").fetchall()

    return render_template('index.html', pages=pages, search_query=search_query, sort_by=sort_by)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            user_obj = User(id=user['id'], username=user['username'], role=user['role'])
            login_user(user_obj)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials!", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    with get_db_connection() as conn:
        # Check if this is the first registered user
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            # First user becomes admin, others default to viewer
            role = 'admin' if user_count == 0 else 'viewer'
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            try:
                conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                             (username, hashed_password, role))
                conn.commit()
                flash(f"Account created successfully! Your role is **{'Admin' if role == 'admin' else 'Viewer'}**.", "success")
            except sqlite3.IntegrityError:
                flash("Username already exists!", "danger")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/create', methods=['GET', 'POST'])
@role_required('admin', 'editor')
def create_page():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        raw_content = request.form.get('content')
        try:
            parsed_content = json.loads(raw_content) if raw_content else {}
        except json.JSONDecodeError:
            flash("Error saving content. Invalid JSON format.", "danger")
            return redirect(url_for('create_page'))
        with get_db_connection() as conn:
            conn.execute("INSERT INTO pages (name, description, content) VALUES (?, ?, ?)", 
                         (name, description, json.dumps(parsed_content)))
            conn.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('index'))
    return render_template('create.html')

@app.route('/edit/<int:page_id>', methods=['GET', 'POST'])
@role_required('admin', 'editor')
def edit_page(page_id):
    with get_db_connection() as conn:
        page = conn.execute("SELECT * FROM pages WHERE id = ?", (page_id,)).fetchone()
    if not page:
        flash("Page not found.", "danger")
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        raw_content = request.form.get('content')
        try:
            parsed_content = json.loads(raw_content) if raw_content else {}
        except json.JSONDecodeError:
            flash("Error saving content. Invalid JSON format.", "danger")
            return redirect(url_for('edit_page', page_id=page_id))
        # Save old version before updating
        with get_db_connection() as conn:
            conn.execute("INSERT INTO page_versions (page_id, name, description, content) VALUES (?, ?, ?, ?)", 
                         (page_id, page['name'], page['description'], page['content']))
            conn.execute("UPDATE pages SET name = ?, description = ?, content = ? WHERE id = ?", 
                         (name, description, json.dumps(parsed_content), page_id))
            conn.commit()
        flash("Page updated successfully! Old version saved.", "success")
        return redirect(url_for('index'))
    return render_template('edit.html', page=page)

@app.route('/delete_page/<int:page_id>', methods=['POST'])
@role_required('admin', 'editor')
def delete_page(page_id):
    with get_db_connection() as conn:
        page = conn.execute("SELECT * FROM pages WHERE id = ?", (page_id,)).fetchone()
        if not page:
            flash("Page not found!", "danger")
            return redirect(url_for('index'))
        conn.execute("DELETE FROM pages WHERE id = ?", (page_id,))
        conn.commit()
    flash("Page deleted successfully!", "success")
    return redirect(url_for('index'))

@app.route('/users')
@role_required('admin')
def user_management():
    with get_db_connection() as conn:
        users = conn.execute("SELECT id, username, role FROM users").fetchall()
    return render_template('users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('user_management'))

@app.route('/page/<int:page_id>')
def view_page(page_id):
    with get_db_connection() as conn:
        page = conn.execute("SELECT * FROM pages WHERE id = ?", (page_id,)).fetchone()
    if not page:
        flash("Page not found.", "danger")
        return redirect(url_for('index'))
    try:
        data = json.loads(page['content']) if page['content'] else {}
    except json.JSONDecodeError:
        flash("Error loading page content. Invalid format.", "danger")
        data = {}
    sanitized_html = sanitize_html(data.get("html", "<p>No content available.</p>"))
    return render_template('view.html', page=page, sanitized_html=sanitized_html)

# Register `json_loads` as a Jinja2 filter
@app.template_filter('json_loads')
def json_loads_filter(s):
    try:
        return json.loads(s)
    except Exception as e:
        print("JSON load error:", e)
        return {}

@app.route('/admin/users', methods=['GET', 'POST'])
@role_required('admin')
def admin_users():
    search_query = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    sql_query = "SELECT id, username, role FROM users WHERE 1=1"
    params = []
    if search_query:
        sql_query += " AND username LIKE ?"
        params.append(f"%{search_query}%")
    if role_filter in ['admin', 'editor', 'viewer']:
        sql_query += " AND role = ?"
        params.append(role_filter)
    with get_db_connection() as conn:
        users = conn.execute(sql_query, params).fetchall()
    return render_template('admin_users.html', users=users, search_query=search_query, role_filter=role_filter)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        with get_db_connection() as conn:
            if new_password:  # If the admin wants to update the password
                hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
                conn.execute("UPDATE users SET username = ?, password = ? WHERE id = ?", (new_username, hashed_password, user_id))
            else:
                conn.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
            conn.commit()
        flash("User details updated successfully!", "success")
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

@app.route('/page_versions/<int:page_id>')
@role_required('admin')
def view_page_versions(page_id):
    with get_db_connection() as conn:
        versions = conn.execute("SELECT * FROM page_versions WHERE page_id = ? ORDER BY saved_at DESC", (page_id,)).fetchall()
    return render_template('page_versions.html', versions=versions, page_id=page_id)

@app.route('/restore_version/<int:version_id>', methods=['POST'])
@role_required('admin')
def restore_version(version_id):
    with get_db_connection() as conn:
        version = conn.execute("SELECT * FROM page_versions WHERE id = ?", (version_id,)).fetchone()
        if not version:
            flash("Version not found!", "danger")
            return redirect(url_for('index'))
        # Restore page to this version
        conn.execute("UPDATE pages SET name = ?, description = ?, content = ? WHERE id = ?", 
                     (version['name'], version['description'], version['content'], version['page_id']))
        conn.commit()
    flash("Page restored to previous version!", "success")
    return redirect(url_for('view_page', page_id=version['page_id']))

if __name__ == '__main__':
    app.run(debug=True)
