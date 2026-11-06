from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import uuid
import analyzer

app = Flask(__name__)

UPLOAD_FOLDER = "web_uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded_file = request.files.get("email_file")

    if not uploaded_file or uploaded_file.filename == "":
        return "No email file selected.", 400

    if not uploaded_file.filename.lower().endswith(".eml"):
        return "Only .eml files are allowed.", 400

    filename = secure_filename(uploaded_file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_name
    )

    uploaded_file.save(file_path)

    try:
        result = analyzer.analyze_email(file_path)

        return render_template(
            "result.html",
            result=result,
            filename=filename
        )

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


if __name__ == "__main__":
    app.run(debug=True)