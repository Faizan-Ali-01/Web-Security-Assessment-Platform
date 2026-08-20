from typing import Any, Dict

from scanner.cookie_checker import analyze_cookies
from scanner.cors_checker import analyze_cors
from scanner.endpoint_discovery import analyze_html_resources
from scanner.exposure_checker import analyze_information_exposure
from scanner.finding_engine import (
    build_findings,
    calculate_security_score,
    get_score_rating,
)
from scanner.headers_checker import analyze_security_headers
from scanner.http_checker import check_website_url
from scanner.javascript_analyzer import analyze_javascript
from scanner.method_checker import analyze_http_methods
from scanner.ssl_checker import check_ssl_certificate
from scanner.technology_checker import analyze_technologies


def run_scan(target_url: str) -> Dict[str, Any]:
    http_result = check_website_url(target_url)
    scan_succeeded = bool(http_result.get("ok"))

    result: Dict[str, Any] = {
        "scan_status": "Success" if scan_succeeded else "Failed",
        "status": "Success" if scan_succeeded else "Failed",
        "target_url": http_result.get("url") or target_url,
        "final_url": http_result.get("final_url"),
        "http_result": http_result,
        "security_headers": [],
        "ssl_result": {},
        "information_exposure": [],
        "cookies": [],
        "cors_results": [],
        "http_methods": [],
        "technologies": [],
        "endpoint_discovery": {
            "links": [],
            "forms": [],
            "scripts": [],
            "stylesheets": [],
            "images": [],
            "iframes": [],
            "internal_urls": [],
            "external_domains": [],
            "api_candidates": [],
        },
        "javascript_analysis": {"endpoint_candidates": []},
        "findings": [],
        "score": None,
        "rating": "Failed" if not scan_succeeded else None,
        "error": http_result.get("error"),
    }

    if not scan_succeeded:
        return result

    headers = http_result.get("headers", {})
    result["security_headers"] = analyze_security_headers(headers)
    result["ssl_result"] = check_ssl_certificate(target_url)
    result["information_exposure"] = analyze_information_exposure(headers)
    result["cookies"] = analyze_cookies(headers)
    result["cors_results"] = analyze_cors(headers)
    result["http_methods"] = analyze_http_methods(headers)
    result["technologies"] = analyze_technologies(headers)
    result["endpoint_discovery"] = analyze_html_resources(
        http_result.get("body", ""),
        http_result.get("final_url") or http_result.get("url") or target_url,
    )
    result["javascript_analysis"] = analyze_javascript(
        http_result.get("body", ""),
        http_result.get("final_url") or http_result.get("url") or target_url,
    )
    result["findings"] = build_findings(
        http_result,
        result["security_headers"],
        result["ssl_result"],
        result["cors_results"],
    )
    result["score"] = calculate_security_score(result["findings"])
    result["rating"] = get_score_rating(result["score"])

    return result


__all__ = ["run_scan"]
