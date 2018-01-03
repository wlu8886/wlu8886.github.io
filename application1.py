from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
import numbers
import sqlite3

from helpers import apology, login_required, usd

# Basic structure taken from CS50 Finance
# Configure application
app = Flask(__name__)

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///crimsoncloset.db")


@app.route("/")
def homePage():
    # If user is logged in, return them to the main user page
    if "user_id" in session:
        return render_template("mainPage.html")
    else:
        # If user is not logged in, return them to the home page
        return render_template("layout.html")


@app.route("/mainPage", methods=["GET"])
@login_required
def mainPage():
    # Retrieve information for all clothing uploads
    portfolio = db.execute("SELECT username, clothingName, size, price, picture, buy_rent FROM portfolio")

    for clothes in portfolio:
        clothes["price"] = usd(clothes["price"])

    return render_template("mainPage.html", portfolio=portfolio)


@app.route("/buy", methods=["GET"])
@login_required
def buy():
    """View all sale options"""

    # Retrieve information for all clothes for sale
    buy = db.execute("SELECT username, clothingName, size, price, picture FROM portfolio WHERE buy_rent=:buy", buy="sell")

    for clothes in buy:
        clothes["price"] = usd(clothes["price"])

    return render_template("buy.html", buy=buy)


@app.route("/rent", methods=["GET"])
@login_required
def rent():
    """View all rent options"""

    # Retrieve information for all clothes for rent
    rent = db.execute("SELECT user_id, clothingName, size, price, picture FROM portfolio WHERE buy_rent=:rent", rent="rent")

    for clothes in rent:
        clothes["price"] = usd(clothes["price"])

    return render_template("rent.html", rent=rent)


@app.route("/modal_contact", methods=["POST"])
def modal_contact():
    """Send messages from modals"""

    # Retrieve message and message recipient from modal html form
    recipient = request.form.get("recipient")
    message = request.form.get("message")

    # Retrieve the user's username from the database
    username = db.execute("SELECT username FROM users WHERE id=:user_id",
                          user_id=session["user_id"])[0]["username"]
    db.execute("INSERT INTO messages (sender, recipient, message) VALUES (:sender, :recipient, :message)",
               sender=username, recipient=recipient, message=message)

    return redirect("/mainPage")


@app.route("/delete_upload", methods=["POST"])
def delete_upload():
    """Delete uploads"""

    # Retrieve the clothing item to be deleted
    clothingId = request.form.get("clothingId")
    # Delete the clothing item from the user's portfolio
    db.execute("DELETE FROM portfolio WHERE ID=:clothingId", clothingId=clothingId)

    return redirect("/profile")


@app.route("/delete_message", methods=["POST"])
def delete_message():
    """Delete messages"""

    # Retrieve the message to be deleted
    message = request.form.get("message")
    # Delete the clothing item from the user's portfolio
    db.execute("DELETE FROM messages WHERE message=:message", message=message)

    return redirect("/message")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    if "user_id" in session:
        return redirect("/mainPage")

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash('Please enter your username.')
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            #flash('Please enter your password.')
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash('Username and/or password are not correct.')
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to user's main page
        return redirect("/mainPage")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Upload a clothing item"""
    if request.method == "POST":
        name = db.execute("SELECT name FROM users WHERE id = :user_id",
                          user_id=session["user_id"])[0]["name"]
        username = db.execute("SELECT username FROM users WHERE id = :user_id",
                              user_id=session["user_id"])[0]["username"]
        email = db.execute("SELECT email FROM users WHERE id = :user_id",
                           user_id=session["user_id"])[0]["email"]

        pic = request.files.get("picture")
        price = request.form.get("price")
        cName = request.form.get("clothingName")
        sz = request.form.get("size")
        type = request.form.get("profitType")

        filename = "static/images/" + pic.filename
        pic.save(filename)

        if not pic:
            flash('Please upload a photo.')
            return render_template("profile.html", name=name, username=username, email=email)
        if not price:
            flash('Please enter a price.')
            return render_template("profile.html", name=name, username=username, email=email)
        if not cName:
            flash('Please enter a clothing description.')
            return render_template("profile.html", name=name, username=username, email=email)
        if not sz:
            flash('Please select a size.')
            return render_template("profile.html", name=name, username=username, email=email)

        db.execute("INSERT INTO portfolio (clothingName, size, price, picture, user_id, buy_rent, username) VALUES (:clothingName, :size, :price, :picture, :user_id, :buy_rent, :username)",
                   clothingName=cName, size=sz, price=price, picture=filename, user_id=session["user_id"], buy_rent=type, username=username)

        return redirect("/mainPage")
    else:
        name = db.execute("SELECT name FROM users WHERE id = :user_id", user_id=session["user_id"])
        username = db.execute("SELECT username FROM users WHERE id = :user_id",
                              user_id=session["user_id"])
        email = db.execute("SELECT email FROM users WHERE id = :user_id",
                           user_id=session["user_id"])

        portfolio = db.execute("SELECT ID, picture, clothingName FROM portfolio WHERE user_id = :user_id", user_id=session["user_id"])

        return render_template("profile.html", name=name, username=username, email=email, portfolio=portfolio)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Retrieve name, username, email, password, and confirmation from user
        name = request.form.get("name")
        uname = request.form.get("username")
        em = request.form.get("email")
        pword = request.form.get("password")
        confirm = request.form.get("confirmation")

        # Check if name, username, email, password, and confirmation are valid
        if not name:
            flash('Please enter your name.')
            return render_template("register.html")
        if not uname:
            flash('Please enter a username.')
            return render_template("register.html")
        if not pword:
            flash('Please enter a password.')
            return render_template("register.html")
        if not confirm:
            flash('Please enter a password confirmation.')
            return render_template("register.html")
        if not em:
            flash('Please enter your email.')
            return render_template("register.html")

        # Check that username has not already been taken
        existUser = db.execute("SELECT * FROM users WHERE username = :uname", uname=uname)
        if int(len(existUser)) > 0:
            flash('That username is already taken. Please enter another.')
            return render_template("register.html")

        # Check that password matches password confirmation
        if pword != confirm:
            flash('Password and password confirmation do not match.')
            return render_template("register.html")

        # Create a hash for the password
        pword = generate_password_hash(pword)

        # Enters user into users table
        result = db.execute("INSERT INTO users (name, username, hash, email) VALUES(:name, :username, :hash, :email)",
                            name=name, username=uname, hash=pword, email=em)
        session["user_id"] = result

        return redirect("/mainPage")

    else:
        return render_template("register.html")


@app.route("/message", methods=["GET", "POST"])
@login_required
def messenger():
    """Enable messaging between users"""
    if request.method == "POST":

        # Retrieve sender, receiver, and message
        sender = db.execute("SELECT username FROM users WHERE id = :user_id",
                            user_id=session["user_id"])[0]["username"]
        recipient = request.form.get("recipient")
        message = request.form.get("message")

        # Check if recipient form is filled
        if not recipient:
            flash('Please enter recipient username.')
            return render_template("messenger.html")

        # Checks for valid recipient username
        users = db.execute("SELECT * FROM users WHERE username=:recipient", recipient=recipient)
        if not int(len(users)) > 0:
            flash('Please enter a valid username.')
            return render_template("messenger.html")

        # Check if message is valid and exists
        if not message:
            flash('  Please enter a message.')
            return render_template("messenger.html")

        # Add message into messages database
        messages = db.execute("INSERT INTO messages (sender, recipient, message) VALUES (:sender, :recipient, :message)",
                              sender=sender, recipient=recipient, message=message)

        return redirect("/mainPage")

    else:
        username = db.execute("SELECT username FROM users WHERE id = :user_id",
                              user_id=session["user_id"])[0]["username"]
        inbox = db.execute("SELECT sender, message, timestamp FROM messages WHERE recipient=:username", username=username)

        return render_template("messenger.html", inbox=inbox)


@app.route("/changePassword", methods=["GET", "POST"])
def changePassword():
    """Change password"""
    if request.method == "POST":

        # Retrieve current password, new password, and new confirmation from user
        pword = request.form.get("password")
        new_pword = request.form.get("newPassword")
        confirm = request.form.get("newConfirm")

        # Check if current password, new password, and new confirmation are valid
        if not new_pword:
            flash('Please enter a new password.')
            return render_template("changePassword.html")

        if not pword:
            flash('Please enter current password.')
            return render_template("changePassword.html")

        if not confirm:
            flash('Missing new password confirmation!')
            return render_template("changePassword.html")

        # Retrieve all info for that user
        rows = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id=session["user_id"])

        # Check that new password is valid
        if not check_password_hash(rows[0]["hash"], pword):
            flash('Please enter a different password.')
            return render_template("changePassword.html")

        # Check that password matches password confirmation
        if new_pword != confirm:
            flash('Password confirmation is different from password entered.')
            return render_template("changePassword.html")

        # Check that new password is different from old password
        if pword == new_pword:
            flash('New password must be different from current password.')
            return render_template("changePassword.html")

        # Create a hash for the new password
        new_hash = generate_password_hash(new_pword)

        # Update user's information into users table
        result = db.execute(
            "UPDATE users SET hash = :new_hash WHERE id = :user_id",
            user_id=session["user_id"], new_hash=new_hash)

        return redirect("/mainPage")

    else:
        return render_template("changePassword.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
