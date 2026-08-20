import re
from typing import Any, Dict, List

from scanner.cors_checker import analyze_cors
from scanner.exposure_checker import analyze_information_exposure
from scanner.finding_engine import build_findings
from scanner.headers_checker import analyze_security_headers
from scanner.cookie_checker import analyze_cookies
from scanner.technology_checker import analyze_technologies


JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _observation(category: str, title: str, description: str, evidence: str, recommendation: str) -> Dict[str, str]:
    return {
        "category": category,
        "title": title,
        "severity": "info",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def analyze_imported_request(request_data: Dict[str, Any]) -> List[Dict[str, str]]:
    observations: List[Dict[str, str]] = []
    headers = {str(key).lower(): str(value) for key, value in request_data.get("headers", {}).items()}
    parameters = request_data.get("parameters", [])
    method = request_data.get("method", "")
    path = request_data.get("path", "")

    if not headers.get("host"):
        observations.append(_observation("Request Metadata", "Missing Host header", "The imported request does not include a Host header.", "Host header absent", "Confirm the request target and host routing before replaying this evidence."))
    if headers.get("authorization"):
        observations.append(_observation("Authentication", "Authorization header present", "An Authorization header is present in the imported request.", "Authorization header present", "Review the authentication scheme and protect this evidence as sensitive."))
    if request_data.get("cookies"):
        observations.append(_observation("Session", "Cookie present", "The request includes one or more cookies.", ", ".join(request_data["cookies"].keys()), "Review session cookie scope and handling."))
    if any("session" in name.lower() or "auth" in name.lower() for name in request_data.get("cookies", {})):
        observations.append(_observation("Session", "Session-like cookie", "A cookie name appears related to session or authentication state.", ", ".join(request_data["cookies"].keys()), "Review session management and cookie protections."))
    if method in {"TRACE", "OPTIONS"} or method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        observations.append(_observation("Potential Attack Surface", f"Unusual HTTP method: {method}", "The imported request uses a method that may warrant review.", method, "Confirm that this method is expected and appropriately restricted."))
    if path.lower().startswith(("/api", "/graphql", "/rest/", "/v1/", "/v2/")):
        observations.append(_observation("API", "Potential API endpoint", "The request path resembles an API endpoint; this is an investigative candidate, not confirmation.", path, "Review authentication, authorization, input handling, and response behavior."))
    if request_data.get("content_type", "").lower().startswith("application/json"):
        observations.append(_observation("API", "JSON API request", "The request body is labeled as JSON and may represent an API interaction.", request_data["content_type"], "Review schema validation and authorization behavior."))
    if request_data.get("content_type", "").lower().startswith("application/x-www-form-urlencoded"):
        observations.append(_observation("Request Metadata", "Form submission", "The request contains URL-encoded form data.", request_data["content_type"], "Review sensitive form parameters and server-side validation."))

    seen_parameter_names = set()
    sensitive_names = ("password", "token", "secret", "api_key", "apikey", "authorization")
    for parameter in parameters:
        name = parameter.get("name", "")
        lower_name = name.lower()
        if name in seen_parameter_names:
            continue
        seen_parameter_names.add(name)
        if any(item in lower_name for item in sensitive_names) or JWT_PATTERN.match(parameter.get("value", "")):
            observations.append(_observation("Parameters", f"Sensitive parameter: {name}", "A parameter name or value appears sensitive.", f"{parameter.get('location')}: {name}", "Handle this value as sensitive and review authentication or secret management."))
        elif any(item in lower_name for item in ("redirect", "return", "next", "url")):
            observations.append(_observation("Parameters", "Potential redirect parameter", "A parameter may influence a redirect or destination URL.", f"{parameter.get('location')}: {name}", "Review whether the application validates redirect destinations."))
        elif "file" in lower_name or "upload" in lower_name:
            observations.append(_observation("Potential Attack Surface", "Potential file parameter", "A parameter name suggests file or upload handling.", f"{parameter.get('location')}: {name}", "Review file type, size, storage, and authorization controls."))
        elif any(item in lower_name for item in ("admin", "debug", "id")):
            observations.append(_observation("Parameters", f"Review parameter: {name}", "A parameter name may expose an administrative, debugging, or object identifier input.", f"{parameter.get('location')}: {name}", "Review authorization, input validation, and information exposure."))

    return observations


def analyze_imported_response(response: Dict[str, Any]) -> Dict[str, Any]:
    headers = response.get("headers", {})
    security_headers = analyze_security_headers(headers)
    ssl_result: Dict[str, Any] = {}
    cors_results = analyze_cors(headers)
    findings = build_findings({}, security_headers, ssl_result, cors_results)
    return {
        "security_headers": security_headers,
        "information_exposure": analyze_information_exposure(headers),
        "cookies": analyze_cookies(headers),
        "cors_results": cors_results,
        "technologies": analyze_technologies(headers),
        "findings": findings,
    }


__all__ = ["analyze_imported_request", "analyze_imported_response"]
