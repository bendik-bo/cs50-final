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
def get_db():
    """Establish database connection for request"""
    if "db" not in g:
        g.db = sqlite3.connect("database.db")
        g.db.row_factory = sqlite3.Row
    return g.db.cursor()

@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request"""
    if "db" in g:
        g.db.close()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""
    if request.method == "POST":
        db = get_db()

        # Empty username field
        if not request.form.get("username"):
            flash("Please fill in a username", "username")
            return redirect("/signup")

        # Username already taken
        if db.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")]).fetchone():
            flash("Username already exists", "username")
            return redirect("/signup")

        # Empty password field
        if not request.form.get("password") or not request.form.get("confirm"):
            flash("Fill in both password-fields", "password")
            return redirect("/signup")

        # Password mismatch
        if request.form.get("password") != request.form.get("confirm"):
            flash("Passwords do not match", "password")
            return redirect("/signup")

        # Insert user into database
        # db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))

        return redirect("/")

    else:
        return render_template("signup.html")