import os
from os import path

from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import login_required, query_db, insert_db, allowed_file, file_size, validate_create, validate_submit

USER_IMAGES = "./static/images/users/"
DEFAULT_AVATAR = "./static/images/Default-profile.jpg"
MAX_FILE_SIZE = 5 * 1024 * 1024
CATEGORIES = ["General Knowledge", "Science", "Technology", "Nature", "History", "Geography", "Pop Culture", "Music", "Movies & TV", "Sports", "Literature", "Food", "Other"]


app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SECRET_KEY"] = "nf0{8/%+8z0cd%$n[eq4ve7ab7)@6"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
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

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("Please fill in a username", "failUsername")
            return redirect("/login")

        elif not password:
            flash("Please fill in a password", "failPassword")
            return render_template("login.html", username=username)

        rows = query_db("SELECT * FROM users WHERE username = ?", [username])

        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], password):
            flash("Incorrect username or password", "failUsername")
            return render_template("login.html", username=username)

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
        try: 
            file = request.files["file"]
        except KeyError:
            flash("No file part." "failUpload")
            return redirect("/profile")

        if file.filename == "":
            flash("No selected file", "failUpload")
            return redirect("/profile")

        elif not allowed_file(file.filename):
            flash("Invalid file type", "failUpload")
            return redirect("/profile")
        
        elif file_size(file) > MAX_FILE_SIZE:
            flash("File size exceeds the allowed limit.", "failUpload")
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


        if amount:
            try: 
                amount = int(amount)
            except ValueError:
                flash("Invalid datatype in 'number of questions'.", "failCreate")
                return render_template("create.html", title=title, quiztype=quiztype, categories=CATEGORIES)

        if not validate_create(title, quiztype, amount):
            return render_template("create.html", title=title, quiztype=quiztype, amount=amount, categories=CATEGORIES)
        else:
            session["quiz_data"] = {
                "title": title,
                "category": category,
                "type": quiztype,
                "amount": amount
            }
            return render_template("create.html", title=title, quiztype=quiztype, amount=amount, categories=CATEGORIES, generate_questions=True)
    else: 
        return render_template("create.html", categories=CATEGORIES)


@app.route("/submit", methods=["POST"])
@login_required
def submit():
    """Stores the quiz in DB and redirects to said quiz page"""

    quiz_data = session["quiz_data"]
    questions = []
    answers = []
    correct_option = []

    for i in range(quiz_data["amount"]):
        questions.append(request.form.get(f"question{i+1}"))

    if quiz_data["type"] == "bool":
        for i in range(quiz_data["amount"]):
            answers.append(request.form.get(f"bool{i+1}"))

    elif quiz_data["type"] == "enter":
        for i in range(quiz_data["amount"]):
            answers.append(request.form.get(f"answer{i+1}"))

    elif quiz_data["type"] == "multi":
        for i in range(quiz_data["amount"]):
            answers_ = []
            for j in range(3):
                answers_.append(request.form.get(f"answer{i+1}_{j+1}"))
            answers.append(answers_)
            correct_option.append(int(request.form.get(f"correct{i+1}")))

    print(type(correct_option[0]), correct_option)
                
    if not validate_submit(quiz_data["amount"], questions, quiz_data["type"], answers, correct_option):
        return render_template("create.html", amount=quiz_data["amount"], quiztype=quiz_data["type"], title=quiz_data["title"], categories=CATEGORIES, questions=questions, answers=answers, generate_questions=True, correct_option=correct_option)

    session.pop("quiz_data", None)

    


    # quiz_id = insert_db("INSERT INTO quizzes (title, category, creator_id) VALUES (?, ?, ?)", [quiz_data["title"], quiz_data["category"], session["user_id"]])

    # for i in range(quiz_data["amount"]):
    #     question_id = insert_db("INSERT INTO questions (quiz_id, question) VALUES (?, ?)", [questions[i], quiz_id])
        
    #     if quiz_data["type"] == "multi":
    #         for j in range(3):
    #             if j == 
    #             insert_db("INSERT INTO answers (question_id, answer) VALUES (?, ?)", [question_id, answers[i]])
    #     elif quiz_data["type"] == "bool"
    #         insert_db("INSERT INTO answers (question_id, bool) VALUES (?, ?)", [question_id, answers[i]])
    #     else:



    # insert_db("INSERT INTO quizzes (title, category, creator_id) VALUES (?, ?, ?)", [request.form.get("title"), request.form.get("category"), session["user_id"]])
    
    return render_template("create.html")

if __name__ == "__main__":
    app.run(debug=True)