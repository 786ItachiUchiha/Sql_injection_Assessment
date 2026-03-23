from flask import Flask, request
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("users.db")


@app.route("/")
def home():
    return """
    <h2>Secure Login (Parameterized)</h2>
    <form method="GET" action="/login">
        Username: <input name="username"><br>
        Password: <input name="password"><br>
        <input type="submit">
    </form>
    """


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = get_db()
    cursor = conn.cursor()

    # 🔐 SECURE QUERY (Parameterized)
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    try:
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
    except Exception as e:
        conn.close()
        return f"SQL Error: {e}"

    conn.close()

    if result:
        return f"Welcome {result[1]}!"
    else:
        return "Invalid username or password"


if __name__ == "__main__":
    # ✅ Run on different port
    app.run(host="127.0.0.1", port=5001, debug=True)

