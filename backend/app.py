import os
from flask import Flask, abort, flash, redirect, render_template, request, url_for

from burp_parser import parse_http_request, parse_http_response
from database import (
    clear_imported_requests,
    clear_scan_history,
    delete_imported_request,
    delete_scan,
    get_dashboard_stats,
    get_imported_request_count,
    get_findings_by_scan_id,
    get_recent_scans,
    get_request_by_id,
    get_request_findings,
    get_requests,
    get_response_by_request_id,
    get_scan_by_id,
    init_db,
    save_findings,
    save_imported_request,
    save_imported_response,
    save_request_findings,
    save_scan,
)
from scanner.request_analyzer import analyze_imported_request, analyze_imported_response
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
        imported_request_count=get_imported_request_count(),
        recent_requests=get_requests(5),
    )


@app.route("/scans")
def scans():
    return render_template("scans.html", scans=get_recent_scans())


@app.route("/import", methods=["GET", "POST"])
def import_request():
    if request.method == "GET":
        return render_template("import.html")

    raw_request = request.form.get("raw_request", "")
    raw_response = request.form.get("raw_response", "")
    try:
        request_data = parse_http_request(raw_request)
        request_data["indicators"] = analyze_imported_request(request_data)
        response_data = None
        if raw_response.strip():
            response_data = parse_http_response(raw_response)
            response_data["analysis"] = analyze_imported_response(response_data)

        request_id = save_imported_request(request_data)
        if response_data is not None:
            save_imported_response(request_id, response_data)
            save_request_findings(request_id, response_data["analysis"]["findings"])
    except ValueError as exc:
        return render_template("import.html", error=str(exc), raw_request=raw_request, raw_response=raw_response), 400

    flash("Burp request imported successfully.", "success")
    return redirect(url_for("view_request", request_id=request_id))


@app.route("/investigation")
def investigation():
    return redirect(url_for("requests_history"))


@app.route("/requests")
def requests_history():
    return render_template("requests.html", requests=get_requests())


@app.route("/request/<int:request_id>")
def view_request(request_id: int):
    request_data = get_request_by_id(request_id)
    if not request_data:
        abort(404)
    return render_template(
        "investigation.html",
        request_data=request_data,
        response_data=get_response_by_request_id(request_id),
        findings=get_request_findings(request_id),
    )


@app.route("/requests/<int:request_id>/delete", methods=["POST"])
def delete_request_route(request_id: int):
    if delete_imported_request(request_id):
        flash("Imported request deleted successfully.", "success")
    else:
        flash("Imported request not found.", "warning")
    return redirect(url_for("requests_history"))


@app.route("/requests/clear", methods=["POST"])
def clear_requests_route():
    clear_imported_requests()
    flash("Imported request history cleared successfully.", "success")
    return redirect(url_for("requests_history"))


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
            imported_request_count=get_imported_request_count(),
            recent_requests=get_requests(5),
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
    
@app.route("/reports")
def reports():
    scans = get_recent_scans()
    return render_template("reports.html", scans=scans)

if __name__ == "__main__":
    app.run(debug=True)