"""Aegis Lab — KASITLI ZAFİYETLİ hedef uygulama.

⚠️ Yalnızca yerel test/eğitim içindir. Üretimde ASLA çalıştırmayın.
İçerir:
  - /user?id=   : SQL injection (string birleştirme + hata mesajı sızıntısı)
  - /search?q=  : yansıyan (reflected) XSS — kaçışsız çıktı
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
        "<h1>Aegis Lab (kasitli zafiyetli)</h1>"
        "<ul><li><a href='/user?id=1'>/user?id=1</a> (SQLi)</li>"
        "<li><a href='/search?q=test'>/search?q=test</a> (XSS)</li>"
        "<li><a href='/redirect?next=home'>/redirect?next=</a> (Open Redirect)</li></ul>"
    )


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    # ZAFİYET: kullanıcı girdisi sorguya doğrudan birleştiriliyor
    query = f"SELECT id, username FROM users WHERE id = '{uid}'"
    conn = sqlite3.connect(DB)
    try:
        rows = conn.execute(query).fetchall()
        return {"query": query, "rows": rows}
    except Exception as exc:  # ZAFİYET: hata mesajı dışarı sızıyor (error-based SQLi)
        return Response(f"SQL error: {exc}", status=500, mimetype="text/plain")
    finally:
        conn.close()


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # ZAFİYET: kullanıcı girdisi kaçışsız HTML'e basılıyor (reflected XSS)
    return f"<html><body><h2>Arama sonuclari: {term}</h2></body></html>"


@app.route("/redirect")
def open_redirect():
    # ZAFİYET: kullanıcı girdisi doğrulanmadan Location'a yazılıyor (open redirect)
    return redirect(request.args.get("next", "/"), code=302)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001)
