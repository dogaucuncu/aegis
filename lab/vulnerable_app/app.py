"""Aegis Lab — INTENTIONALLY VULNERABLE target application.

⚠️ For local test/education only. NEVER run in production.
Contains:
  - /user?id=   : SQL injection (string concatenation + error message leakage)
  - /search?q=  : reflected XSS — unescaped output
"""
import os
import sqlite3

from flask import Flask, Response, redirect, request

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "lab.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [(1, "admin", "s3cr3t"), (2, "alice", "pw123"), (3, "bob", "hunter2")],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return (
        "<h1>Aegis Lab (intentionally vulnerable)</h1>"
        "<ul><li><a href='/user?id=1'>/user?id=1</a> (SQLi)</li>"
        "<li><a href='/search?q=test'>/search?q=test</a> (XSS)</li>"
        "<li><a href='/redirect?next=home'>/redirect?next=</a> (Open Redirect)</li></ul>"
    )


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    # VULNERABILITY: user input is concatenated directly into the query
    query = f"SELECT id, username FROM users WHERE id = '{uid}'"
    conn = sqlite3.connect(DB)
    try:
        rows = conn.execute(query).fetchall()
        return {"query": query, "rows": rows}
    except Exception as exc:  # VULNERABILITY: the error message leaks out (error-based SQLi)
        return Response(f"SQL error: {exc}", status=500, mimetype="text/plain")
    finally:
        conn.close()


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULNERABILITY: user input is written to HTML without escaping (reflected XSS)
    return f"<html><body><h2>Search results: {term}</h2></body></html>"


@app.route("/redirect")
def open_redirect():
    # VULNERABILITY: user input is written to Location without validation (open redirect)
    return redirect(request.args.get("next", "/"), code=302)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001)
