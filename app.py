from flask import Flask, render_template, request, jsonify
from datetime import datetime
import sqlite3
from pathlib import Path
from feature_extractor import extract_features
from model_utils import load_model, predict_url

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "phishing_history.db"

app = Flask(__name__)
model_bundle = load_model()

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasons TEXT,
                scanned_at TEXT NOT NULL
            )
        """)
        con.commit()

def save_scan(url, result):
    reasons = "; ".join(result["reasons"])
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO scans(url,prediction,confidence,reasons,scanned_at) VALUES(?,?,?,?,?)",
            (url, result["prediction"], result["confidence"], reasons,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        con.commit()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    try:
        features = extract_features(url)
        result = predict_url(url, features, model_bundle)
        save_scan(url, result)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/dashboard")
def dashboard():
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT url,prediction,confidence,reasons,scanned_at "
            "FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
    total = len(rows)
    phishing = sum(1 for r in rows if r[1] == "Phishing")
    legitimate = total - phishing
    return render_template(
        "dashboard.html",
        rows=rows, total=total, phishing=phishing, legitimate=legitimate
    )

if __name__ == "__main__":
    init_db()
    print("Open http://127.0.0.1:5000")
    app.run(debug=True)
