from flask import Flask, request
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("users.db")

@app.route("/")
def home():
    return """
    <h2>SQLi Lab Login</h2>
    <form method="GET" action="/login">
        Username: <input name="username"><br>
        Password: <input name="password"><br>
        <input type="submit">
    </form>
    """

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # 🚨 INTENTIONALLY VULNERABLE QUERY
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    print("Executing:", query)  # Debug

    try:
        cursor.execute(query)
        result = cursor.fetchone()
    except Exception as e:
        return f"SQL Error: {e}"

    if result:
        return f"Welcome {result[1]}!"
    else:
        return "Login failed."

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=6000, debug=True)

