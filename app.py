import os

from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import login_required, DATABASE, query_db, insert_db, allowed_file

USER_IMAGES = "./static/images/users/"
MAX_AVATAR_SIZE = 5 * 1024 * 1024

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SECRET_KEY"] = "nf0{8/%+8z0cd%$n[eq4ve7ab7)@6"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request"""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# Main app
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        # Empty username field
        if not username:
            flash("Please fill in a username", "username")
            return render_template("signup.html")

        # Username already taken
        if query_db("SELECT * FROM users WHERE username = ?", [username]):
            flash("Username already exists", "username")
            return render_template("signup.html", username=username)

        # Empty password field
        if not password or not confirm:
            flash("Fill in both password-fields.", "password")
            return render_template("signup.html", username=username)

        # Password mismatch
        if password != confirm:
            flash("Passwords do not match.", "password")
            return render_template("signup.html", username=username)

        # Insert user into database
        insert_db("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, generate_password_hash(password)])

        return redirect("/login")

    else:
        return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            flash("Please fill in a username", "username")
            return render_template("login.html")

        # Ensure password was submitted
        elif not password:
            flash("Please fill in a password", "password")
            return render_template("login.html", username=username)

        # Query database for username
        rows = query_db("SELECT * FROM users WHERE username = ?", [username])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], password):
            flash("Incorrect username or password", "username")
            return render_template("login.html", username=username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")
    
@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()

    return redirect("/login")


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """Access profile page"""
    test = query_db("SELECT username FROM users WHERE id = ?", [session["user_id"]])
    print(test)
    print(session["user_id"])

    return render_template("profile.html")

@app.route("/upload", methods=["POST"])
def upload():
    """Upload image/avatar"""
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "file")
            return render_template("profile.html")
        
        file = request.files["file"]

        if file.filename == "":
            flash("No selected image", "file")
            return render_template("profile.html")

        if not allowed_file(file.filename):
            flash("Invalid file type", "file")
            return render_template("profile.html")

        if file.content_length > MAX_AVATAR_SIZE:
            flash("Image size exceeds the limit", "file")
            return render_template("profile.html")
        
        print(file.content_length)

        if file:
            username = query_db("SELECT username FROM users WHERE id = ?", [session["user_id"]], one=True)
            filetype = file.filename.rsplit(".", 1)[1]
            filename = secure_filename(username[0] + "." + filetype)
            file.save(os.path.join(USER_IMAGES, filename))

        flash("Upload successfull!", "file")
        return render_template("profile.html")

    else:
        return render_template("profile.html")

if __name__ == "__main__":
    app.run(debug=True)