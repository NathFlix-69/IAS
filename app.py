from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this in production
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Temporary in-memory user store (replace with DB later)
users = {
    "admin": {"password": bcrypt.generate_password_hash("Admin123").decode("utf-8"), "role": "Admin"},
    "user": {"password": bcrypt.generate_password_hash("User123").decode("utf-8"), "role": "User"}
}

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username, users[username]["role"])
    return None

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        role = request.form.get("role", "User")  # allow choosing role
        users[username] = {"password": password, "role": role}
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users and bcrypt.check_password_hash(users[username]["password"], password):
            user = User(username, users[username]["role"])
            login_user(user)
            session["role"] = user.role  # store role in session
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "Admin":
        return render_template("dashboard.html", message="Welcome Admin!", role=current_user.role)
    return render_template("dashboard.html", message="Welcome User!", role=current_user.role)

@app.route("/admin")
@login_required
def admin():
    if session.get("role") != "Admin":  # check role properly
        return "Access Denied", 403
    return render_template("admin.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
