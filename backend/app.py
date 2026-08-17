import os
from flask import Flask, render_template, request

from scanner.headers_checker import analyze_security_headers
from scanner.http_checker import check_website_url
from scanner.ssl_checker import check_ssl_certificate
from scanner.exposure_checker import analyze_information_exposure
from scanner.finding_engine import (
    build_findings,
    calculate_security_score,
    get_score_rating,
)

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
        exposure_results = analyze_information_exposure(result.get("headers", {}))
    else:
        header_results = []
        exposure_results = []

    ssl_result = check_ssl_certificate(website_url)

    findings = build_findings(result, header_results, ssl_result)
    security_score = calculate_security_score(findings)
    score_rating = get_score_rating(security_score)

    return render_template(
        "results.html",
        result=result,
        header_results=header_results,
        ssl_result=ssl_result,
        exposure_results=exposure_results,
        findings=findings,
        security_score=security_score,
        score_rating=score_rating,
    )


if __name__ == "__main__":
    app.run(debug=True)