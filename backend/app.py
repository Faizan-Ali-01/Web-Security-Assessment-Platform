import os
from flask import Flask, abort, flash, redirect, render_template, request, url_for

from database import (
    clear_scan_history,
    delete_scan,
    get_dashboard_stats,
    get_findings_by_scan_id,
    get_recent_scans,
    get_scan_by_id,
    init_db,
    save_findings,
    save_scan,
)
from scanner.headers_checker import analyze_security_headers
from scanner.http_checker import check_website_url
from scanner.method_checker import analyze_http_methods
from scanner.technology_checker import analyze_technologies
from scanner.ssl_checker import check_ssl_certificate
from scanner.exposure_checker import analyze_information_exposure
from scanner.cookie_checker import analyze_cookies
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
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "development-secret-key")
init_db()


@app.route("/")
def home():
    return render_template(
        "dashboard.html",
        dashboard_stats=get_dashboard_stats(),
        recent_scans=get_recent_scans(10),
    )


@app.route("/scans")
def scans():
    return render_template("scans.html", scans=get_recent_scans())


@app.route("/scans/<int:scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id: int):
    if delete_scan(scan_id):
        flash("Scan deleted successfully.", "success")
    else:
        flash("Scan not found.", "warning")
    return redirect(url_for("scans"))


@app.route("/scans/clear", methods=["POST"])
def clear_scans_route():
    clear_scan_history()
    flash("Scan history cleared successfully.", "success")
    return redirect(url_for("scans"))


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id: int):
    scan_record = get_scan_by_id(scan_id)
    if not scan_record:
        abort(404)

    findings = get_findings_by_scan_id(scan_id)
    severity_groups = [
        {
            "label": severity.upper(),
            "class_name": severity,
            "findings": [
                finding
                for finding in findings
                if (finding.get("severity") or "info").lower() == severity
            ],
        }
        for severity in ("high", "medium", "low", "info")
    ]
    return render_template(
        "scan_detail.html",
        scan=scan_record,
        severity_groups=severity_groups,
    )


@app.route("/scan", methods=["POST"])
def scan():
    website_url = request.form.get("website_url")

    if not website_url or not website_url.strip():
        return render_template(
            "dashboard.html",
            error="Please enter a valid website URL.",
            dashboard_stats=get_dashboard_stats(),
            recent_scans=get_recent_scans(10),
        )

    result = check_website_url(website_url)
    scan_succeeded = bool(result.get("ok"))

    if scan_succeeded:
        method_results = analyze_http_methods(result.get("headers", {}))
        technology_results = analyze_technologies(result.get("headers", {}))
        header_results = analyze_security_headers(result.get("headers", {}))
        exposure_results = analyze_information_exposure(result.get("headers", {}))
        cookie_results = analyze_cookies(result.get("headers", {}))
        ssl_result = check_ssl_certificate(website_url)
        findings = build_findings(result, header_results, ssl_result)
        security_score = calculate_security_score(findings)
        score_rating = get_score_rating(security_score)
    else:
        method_results = []
        technology_results = []
        header_results = []
        exposure_results = []
        cookie_results = []
        ssl_result = {}
        findings = []
        security_score = None
        score_rating = "Failed"

    scan_id = save_scan(
        target_url=result.get("url") or website_url,
        final_url=result.get("final_url"),
        status_code=result.get("status_code"),
        score=security_score,
        rating=score_rating,
        finding_count=len(findings),
    )
    save_findings(scan_id, findings)

    return render_template(
        "results.html",
        result=result,
        scan_id=scan_id,
        method_results=method_results,
        technology_results=technology_results,
        header_results=header_results,
        ssl_result=ssl_result,
        exposure_results=exposure_results,
        cookie_results=cookie_results,
        findings=findings,
        security_score=security_score,
        score_rating=score_rating,
    )


if __name__ == "__main__":
    app.run(debug=True)