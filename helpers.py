import sqlite3

from flask import flash, redirect, session, g
from flask_session import Session
from functools import wraps

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}

def login_required(f):
    """Decorate routes to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# Database
DATABASE = "database.db"

def get_db():
    """Establish database connection for request"""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False):
    """Query the database"""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    """Insert into the database"""
    cur = get_db().execute(query, args)
    lastrowid = cur.lastrowid
    get_db().commit()
    cur.close()
    return lastrowid

# File upload
def allowed_file(filename):
    """Check if image has an allowed extension"""
    
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def file_size(file):
    """Checks file size"""

    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size

# Validation
def validate_create(title, quiztype, amount):
    """Validate info recieved in create route"""

    if not title:
        flash("Title field cannot be empty.", "failCreate")
        return False
    elif len(title) > 100:
        flash("Title cannot be longer than 50 characters.", "failCreate")
        return False
    elif not quiztype:
        flash("You must choose a quiz type.", "failCreate")
        return False
    elif not amount:
        flash("You must specify amount of questions.", "failCreate")
        return False
    elif amount > 30 or amount < 1:
        flash("Invalid number of questions.", "failCreate")
        return False
    else:
        return True
    
def validate_submit(amount, questions, quiztype, answers, correct_option):
    """Validate info recieved in submit route"""

    for i in range(amount):
        if not questions[i]:
            flash("Please fill in all the questions.", "failSubmit")
            return False

        elif len(questions[i]) > 255:
            flash("Max question length is 255 characters.", "failSubmit")
            return False
        
        if quiztype == "multi":
            for j in range(3):
                if not answers[i][j]:
                    flash("Please select/fill in all answers", "failSubmit")
                    return False
                elif len(answers[i][j]) > 100:
                    flash("Max answer length is 100 characters.", "failSubmit")
                    return False
            if not correct_option[i]:
                flash("Please select a correct answer for each question.", "failSubmit")
                return False
        else:
            if not answers[i]:
                flash("Please select/fill in all answers", "failSubmit")
                return False
            elif len(answers[i]) > 100:
                flash("Max answer length is 100 characters.", "failSubmit")
                return False
    return True
    

            