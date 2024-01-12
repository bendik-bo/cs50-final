import os
from os import path

from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import login_required, DATABASE, query_db, insert_db, allowed_file

USER_IMAGES = "./static/images/users/"
DEFAULT_AVATAR = "./static/images/Default-profile.jpg"
categories = ["General Knowledge", "Science", "Technology", "Nature", "History", "Geography", "Pop Culture", "Music", "Movies & TV", "Sports", "Literature", "Food", "Other"]

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

        if not password or not confirm:
            flash("Fill in both password-fields.", "failPassword")
            return render_template("signup.html", username=username)

        if password != confirm:
            flash("Passwords do not match.", "failPassword")
            return render_template("signup.html", username=username)
        
        if len(username) > 30 or len(username) < 3:
            flash("Username must be between 3 and 20 characters long.", "failUsername")
            return redirect("/signup")
        
        if len(password) < 8:
            flash("Password must be atleast 8 characters long.", "failPassword")
            return render_template("signup.html", username=username)
  
        if query_db("SELECT * FROM users WHERE username = ?", [username]):
            flash("Username already exists", "failUsername")
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

@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    if request.method == "POST":
        oldpass = request.form.get("oldpass")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        print(oldpass)
        if not oldpass:
            flash("Please fill in previous password", "failOld")
            return redirect("/changepass")
        
        result = query_db("SELECT password_hash FROM users WHERE id = ?", [session["user_id"]], one=True)
        if not check_password_hash(result["password_hash"], oldpass):
            flash("Old password does not match", "failOld")
            return redirect("/changepass")

        if not password or not confirm:
            flash("Please fill in new and confirm password.", "failNew")
            return redirect("/changepass")
        
        if len(password) < 8:
            flash("New password must be more than 8 characters.", "failNew")
            return redirect("/changepass")

        if password != confirm:
            flash("New and confirm passwords do not match.", "failNew")
            return redirect("/changepass")
        
        if oldpass == password:
            flash("New password cannot be the same as previous.", "failNew")
        
        insert_db("UPDATE users SET password_hash = ? WHERE id = ?",  [generate_password_hash(password), session["user_id"]])
        flash("Success! Your password has been updated.", "success")
        return redirect("/profile")

    else:
        return render_template("changepass.html")

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
            previous = query_db("SELECT url FROM images where user_id = ?", [session["user_id"]], one=True)
            if previous["url"] != DEFAULT_AVATAR:
                if os.path.exists(previous["url"]):
                    os.remove(previous["url"])
                else:
                    flash("No previous file found for deletion", "failUpload")
                    return redirect("/profile")

            url = os.path.join(app.config["USER_IMAGES"], filename)
            file.save(url)
            insert_db("UPDATE images SET url = ? WHERE user_id = ?", [url, session["user_id"]])

            flash("Upload successful", "success")
            return redirect("/profile")

        else:
            flash("Error uploading", "failUpload")
            return render_template("profile.html")

    else:
        return render_template("profile.html")
    
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title")
        quiztype = request.form.get("quiztype")
        category = request.form.get("category")
        amount = request.form.get("amount")
        time = request.form.get("time")

        if not title:
            flash("Title field cannot be empty.", "failCreate")
            return redirect("/create")
        
        if len(title) > 50:
            flash("Title cannot be longer than 50 characters.", "failCreate")
            return redirect("/create")

        if not quiztype:
            flash("You must choose a quiz type.", "failCreate")
            return render_template("create.html", title=title, categories=categories)

        if quiztype == "bool":
            checked = "bool"
        elif quiztype == "multi":
            checked = "multi"
        elif quiztype == "enter":
            checked = "enter"
        
        if not amount:
            flash("You must specify amount of questions.", "failCreate")
            return render_template("create.html", title=title, checked=checked, categories=categories)
        
        try: 
            amount = int(amount)
        except ValueError:
            print("Error converting question amount into integer.")

        if amount > 30:
            flash("Number of questions cannot exceed 30", "failCreate")
            return render_template("create.html", title=title, checked=checked, categories=categories)

        session["quiz_data"] = {
            "title": title,
            "category": category,
            "type": quiztype,
            "amount": amount
        }

        return render_template("create.html", amount=amount, quiztype=quiztype, title=title, checked=checked, categories=categories)
    else: 
        return render_template("create.html", categories=categories)


@app.route("/submit", methods=["POST"])
@login_required
def submit():
    """Stores the quiz in DB and redirects to said quiz page"""

    quiz_data = session["quiz_data"]

    questions = []
    for i in range(quiz_data["amount"]):
        questions.append(request.form.get(f"question{i+1}"))

    if quiz_data["type"] == "bool":
        answers = []
        for i in range(quiz_data["amount"]):
            answers.append(request.form.get(f"bool{i+1}"))


    elif quiz_data["type"] == "multi":
        answers = []
        for i in range(quiz_data["amount"]):
            answers_ = []
            for j in range(3):
                answers_.append(request.form.get(f"answer{i+1}_{j+1}"))
            answers.append(answers_)

    print(answers)

    for i in range(quiz_data["amount"]):
        if not questions[i]:
            flash("Please fill in all the questions.", "failSubmit")
            return render_template("create.html", amount=quiz_data["amount"], quiztype=quiz_data["type"], title=quiz_data["title"], checked=quiz_data["type"], categories=categories, questions=questions, answers=answers)
        
        for j in range(3):
            if not answers[i][j]:
                flash("Please select/fill in all answers", "failSubmit")
                return render_template("create.html", amount=quiz_data["amount"], quiztype=quiz_data["type"], title=quiz_data["title"], checked=quiz_data["type"], categories=categories, questions=questions, answers=answers)
        
    session.pop("quiz_data", None)

    # insert_db("INSERT INTO quizzes (title, category, creator_id) VALUES (?, ?, ?)", [request.form.get("title"), request.form.get("category"), session["user_id"]])
    
    return render_template("create.html")

if __name__ == "__main__":
    app.run(debug=True)