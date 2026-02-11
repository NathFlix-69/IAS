from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"  
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Check if we need to add default admin user
    c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if c.fetchone()[0] == 0:
        # Create default admin user with strong password
        admin_hash = bcrypt.generate_password_hash("Admin123!@#").decode('utf-8')
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                 ('admin', admin_hash, 'Admin'))
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def validate_password_strength(password):
    """Validate password meets all criteria"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in '$@#&!' for c in password):
        return False, "Password must contain at least one special character ($@#&!)"
    if ' ' in password:
        return False, "Password cannot contain spaces"
    return True, "Password is strong"

def username_exists(username):
    """Check if username already exists in database"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_user(username):
    """Get user from database"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        username, password_hash, role = result
        return {"username": username, "password": password_hash, "role": role}
    return None

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(username):
    user_data = get_user(username)
    if user_data:
        return User(username, user_data["role"])
    return None

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password_input = request.form["password"]
        role = request.form.get("role", "User")

        # Check if username already exists
        if username_exists(username):
            flash("❌ Username already exists. Please choose a different one.")
            return redirect(url_for("register"))

        # 🚫 Validate password strength
        is_strong, msg = validate_password_strength(password_input)
        if not is_strong:
            flash(f"❌ {msg}")
            return redirect(url_for("register"))

        # Hash password and store in database
        password_hash = bcrypt.generate_password_hash(password_input).decode("utf-8")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, password_hash, role))
            conn.commit()
            flash("✅ Registration successful! You can now login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("❌ Username already exists. Please choose a different one.")
            return redirect(url_for("register"))
        finally:
            conn.close()
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🚫 Validate password strength
        is_strong, msg = validate_password_strength(password)
        if not is_strong:
            flash(f"❌ {msg}")
            return redirect(url_for("login"))

        # Check user in database
        user_data = get_user(username)
        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            user = User(username, user_data["role"])
            login_user(user)
            session["role"] = user.role  
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid username or password")
    
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", 
                         username=current_user.username,
                         role=current_user.role)

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "Admin":  
        flash("❌ Access Denied. Admin privileges required.")
        return redirect(url_for("dashboard"))
    
    # Fetch all users for admin view
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
    users_list = c.fetchall()
    conn.close()
    
    return render_template("admin.html", users=users_list, username=current_user.username)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ You have been logged out successfully.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
