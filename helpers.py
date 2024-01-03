import sqlite3

from flask import redirect, session, g
from functools import wraps

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
    get_db().execute(query, args)
    get_db().commit()


ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}

def allowed_file(filename):
    """Check if image has an allowed extension"""
    
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS