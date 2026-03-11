from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
import os
import hashlib

from modules.disk import run_disk
from modules.memory import run_memory
from modules.network import run_network
from modules.yara_scan import run_yara

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client.dfir
collection = db.results


# ==============================
# Evidence Hash Function
# ==============================

def calculate_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==============================
# Home Page (Upload Interface)
# ==============================

@app.route("/")
def index():
    return render_template("index.html")


# ==============================
# Upload + Run Analysis
# ==============================

@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["file"]
    analysis = request.form["analysis"]

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    # Generate forensic hash
    file_hash = calculate_hash(path)

    if analysis == "disk":
        output = run_disk(path)

    elif analysis == "memory":
        output = run_memory(path)

    elif analysis == "network":
        output = run_network(path)

    elif analysis == "yara":
        output = run_yara(path)

    else:
        output = "Invalid analysis"


    # Detect suspicious results
    alert = None

    if "ERROR" in output or "suspicious" in output.lower():
        alert = "Suspicious activity detected"

    if "malware" in output.lower():
        alert = "Malware signature detected"


    result = {
        "file": file.filename,
        "analysis": analysis,
        "hash": file_hash,
        "result": output,
        "alert": alert
    }

    inserted = collection.insert_one(result)
    result["_id"] = str(inserted.inserted_id)

    return jsonify(result)


# ==============================
# Dashboard Page
# ==============================

@app.route("/results")
def results():

    data = list(collection.find())

    for r in data:
        r["_id"] = str(r["_id"])

    return render_template("dashboard.html", results=data)


# ==============================
# Investigations Page
# ==============================

@app.route("/investigations")
def investigations():

    data = list(collection.find())

    for r in data:
        r["_id"] = str(r["_id"])

    return render_template("investigations.html", results=data)


# ==============================
# Artifacts Page
# ==============================

@app.route("/artifacts")
def artifacts():

    data = list(collection.find())

    return render_template("artifacts.html", results=data)


# ==============================
# Alerts Page
# ==============================

@app.route("/alerts")
def alerts():

    alerts = list(collection.find({
        "alert": {"$ne": None}
    }))

    for a in alerts:
        a["_id"] = str(a["_id"])

    return render_template("alerts.html", alerts=alerts)


# ==============================
# Run Server
# ==============================

if __name__ == "__main__":
    app.run(debug=True)