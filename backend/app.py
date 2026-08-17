import os
from flask import Flask, render_template, request

from scanner.headers_checker import analyze_security_headers
from scanner.http_checker import check_website_url

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path="/static",
)


@app.route("/")
def home():
    return render_template("dashboard.html")


@app.route("/scan", methods=["POST"])
def scan():
    website_url = request.form.get("website_url")

    if not website_url or not website_url.strip():
        return render_template("dashboard.html", error="Please enter a valid website URL.")

    result = check_website_url(website_url)

    if result.get("ok"):
        header_results = analyze_security_headers(result.get("headers", {}))
    else:
        header_results = []

    return render_template("results.html", result=result, header_results=header_results)


if __name__ == "__main__":
    app.run(debug=True)