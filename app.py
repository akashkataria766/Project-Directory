import os

from flask import Flask, render_template, request
from url_checker import analyze_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096

API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        result = analyze_url(url, API_KEY)

    return render_template("index.html", result=result, submitted_url=request.form.get("url", ""))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
