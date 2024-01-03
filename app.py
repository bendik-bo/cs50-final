import os
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Database
DATABASE = "database.db"

def get_db():
    """Establish database connection for request"""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request"""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    """Query the database"""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    """Insert into the database"""
    get_db().execute(query, args)
    get_db().commit()

# Main
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


@app.route("/profile", methods=["GET", "POST"])
def profile():
    return render_template("profile.html")

if __name__ == "__main__":
    app.run(debug=True)