from flask import Flask, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
import sqlite3
import os
import random

app = Flask(__name__)
app.secret_key = "secretkey123"

bcrypt = Bcrypt(app)

DB = "database/users.db"

if not os.path.exists("database"):
    os.makedirs("database")


def init_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if len(password) < 8:
            return "Password must contain at least 8 characters"

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, email, hashed)
            )
            conn.commit()

        except:
            return "Email already exists."

        finally:
            conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        if user:

            stored_password = user[3]

            if bcrypt.check_password_hash(
                    stored_password,
                    password):

                otp = random.randint(100000, 999999)

                session["otp"] = str(otp)
                session["email"] = email

                print("OTP:", otp)

                return redirect("/otp")

        return "Invalid Email or Password"

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():

    if request.method == "POST":

        entered = request.form["otp"]

        if entered == session.get("otp"):

            session["user"] = session["email"]

            session.pop("otp")

            return redirect("/dashboard")

        return "Invalid OTP"

    return render_template("otp.html")


@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
