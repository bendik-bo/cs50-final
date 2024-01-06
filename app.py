import os
from os import path

from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import login_required, DATABASE, query_db, insert_db, allowed_file

USER_IMAGES = "./static/images/users/"
DEFAULT_AVATAR = "./static/images/Default-profile.jpg"

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SECRET_KEY"] = "nf0{8/%+8z0cd%$n[eq4ve7ab7)@6"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config["USER_IMAGES"] = USER_IMAGES

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

        if not username:
            flash("Please fill in a username", "failUsername")
            return redirect("/signup")

        if query_db("SELECT * FROM users WHERE username = ?", [username]):
            flash("Username already exists", "failUsername")
            return render_template("signup.html", username=username)

        if not password or not confirm:
            flash("Fill in both password-fields.", "failPassword")
            return render_template("signup.html", username=username)

        if password != confirm:
            flash("Passwords do not match.", "failPassword")
            return render_template("signup.html", username=username)

        insert_db("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, generate_password_hash(password)])
        result = query_db("SELECT id FROM users WHERE username = ?", [username], one=True)
        id = result["id"]
        insert_db("INSERT INTO images (user_id, url) VALUES (?, ?)", [id, DEFAULT_AVATAR])

        return render_template("login.html", username=username)

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
            flash("Please fill in a username", "failUsername")
            return redirect("/login")

        # Ensure password was submitted
        elif not password:
            flash("Please fill in a password", "failPassword")
            return render_template("login.html", username=username)

        # Query database for username
        rows = query_db("SELECT * FROM users WHERE username = ?", [username])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], password):
            flash("Incorrect username or password", "failUsername")
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

    result = query_db("SELECT url FROM images where user_id = ?", [session["user_id"]], one=True)
    return render_template("profile.html", url=result["url"])

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    """Upload image/avatar"""
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "failUpload")
            return redirect("/profile")
        
        file = request.files["file"]

        if file.filename == "":
            flash("No selected file", "failUpload")
            return redirect("/profile")

        if not allowed_file(file.filename):
            flash("Invalid file type", "failUpload")
            return redirect("/profile")

        if file:
            username = query_db("SELECT username FROM users WHERE id = ?", [session["user_id"]], one=True)
            filetype = file.filename.rsplit(".", 1)[1]
            filename = secure_filename(username[0] + "." + filetype)
            url = os.path.join(app.config["USER_IMAGES"], filename)
            file.save(url)
            insert_db("UPDATE images SET url = ? WHERE user_id = ?", [url, session["user_id"]])

            flash("Upload successful", "successUpload")
            return redirect("/profile")

        else:
            flash("Error uploading", "failUpload")
            return render_template("profile.html")

    else:
        return render_template("profile.html")

if __name__ == "__main__":
    app.run(debug=True)