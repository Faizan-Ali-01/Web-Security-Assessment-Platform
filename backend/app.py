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
from scanner.service import run_scan

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

    scan_result = run_scan(website_url)
    result = scan_result["http_result"]
    findings = scan_result["findings"]
    security_score = scan_result["score"]
    score_rating = scan_result["rating"]

    scan_id = save_scan(
        target_url=scan_result["target_url"],
        final_url=scan_result["final_url"],
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
        method_results=scan_result["http_methods"],
        technology_results=scan_result["technologies"],
        endpoint_discovery=scan_result["endpoint_discovery"],
        javascript_analysis=scan_result["javascript_analysis"],
        cors_results=scan_result["cors_results"],
        header_results=scan_result["security_headers"],
        ssl_result=scan_result["ssl_result"],
        exposure_results=scan_result["information_exposure"],
        cookie_results=scan_result["cookies"],
        findings=findings,
        security_score=security_score,
        score_rating=score_rating,
    )


if __name__ == "__main__":
    app.run(debug=True)