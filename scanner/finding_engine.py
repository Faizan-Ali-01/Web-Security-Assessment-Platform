from typing import Dict, List, Any

def build_findings(
    http_result: Dict[str, Any],
    header_results: List[Dict[str, Any]],
    ssl_result: Dict[str, Any],
    cors_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    _add_http_findings(findings, http_result)
    _add_header_findings(findings, header_results)
    _add_ssl_findings(findings, ssl_result)
    _add_cors_findings(findings, cors_results)

    return findings


def _add_cors_findings(
    findings: List[Dict[str, Any]], cors_results: List[Dict[str, Any]]
) -> None:
    finding_types = {
        "Permissive CORS with Credentials": "high",
        "Wildcard CORS Origin": "low",
    }
    existing_types = {
        finding.get("title")
        for finding in findings
        if finding.get("category") == "CORS"
    }

    for observation in cors_results or []:
        title = observation.get("type")
        severity = finding_types.get(title)
        if not severity or title in existing_types:
            continue

        findings.append(
            {
                "title": title,
                "category": "CORS",
                "severity": severity,
                "description": observation.get("description", ""),
                "evidence": f"CORS value: {observation.get('value', '')}",
                "recommendation": observation.get("recommendation", ""),
            }
        )
        existing_types.add(title)

def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    score = 100
    severity_penalties = {
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        penalty = severity_penalties.get(severity, 0)
        score -= penalty

    return max(score, 0)

def get_score_rating(score: int) -> str:
    if 90 <= score <= 100:
        return "Excellent"
    elif 75 <= score <= 89:
        return "Good"
    elif 60 <= score <= 74:
        return "Fair"
    elif 40 <= score <= 59:
        return "Poor"
    else:
        return "Critical"

def _add_http_findings(
    findings: List[Dict[str, Any]], http_result: Dict[str, Any]
) -> None:
    if not http_result:
        return

    final_url = http_result.get("final_url", "")

    if final_url and final_url.lower().startswith("http://"):
        findings.append(
            {
                "title": "HTTPS Not Used",
                "category": "Transport Security",
                "severity": "medium",
                "description": "The website does not use HTTPS encryption. This exposes sensitive data transmitted between the client and server to man-in-the-middle attacks.",
                "evidence": f"Final URL: {final_url}",
                "recommendation": "Implement HTTPS with a valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS.",
            }
        )

def _add_header_findings(
    findings: List[Dict[str, Any]], header_results: List[Dict[str, Any]]
) -> None:
    if not header_results:
        return

    for header in header_results:
        if not header.get("present"):
            severity = header.get("severity", "low").lower()
            findings.append(
                {
                    "title": f"Missing {header.get('name', 'Security Header')}",
                    "category": "HTTP Headers",
                    "severity": severity,
                    "description": header.get("explanation", "Security header is missing."),
                    "evidence": f"Header '{header.get('name')}' not found in HTTP response.",
                    "recommendation": f"Add the {header.get('name')} header to your HTTP responses.",
                }
            )

def _add_ssl_findings(
    findings: List[Dict[str, Any]], ssl_result: Dict[str, Any]
) -> None:
    if not ssl_result:
        return

    error = ssl_result.get("error")
    is_valid = ssl_result.get("is_valid")
    is_https = ssl_result.get("is_https")
    certificate_present = ssl_result.get("certificate_present")

    if error:
        error_lower = error.lower()

        is_inspection_error = any(
            keyword in error_lower
            for keyword in ["timeout", "dns", "connection", "invalid url", "could not extract"]
        )

        if is_inspection_error:
            return

        findings.append(
            {
                "title": "SSL/TLS Certificate Error",
                "category": "Transport Security",
                "severity": "high",
                "description": f"An SSL/TLS certificate error was detected: {error}",
                "evidence": error,
                "recommendation": "Resolve the SSL/TLS certificate issue. Ensure a valid, trusted certificate is installed and properly configured.",
            }
        )
    elif is_https and certificate_present and not is_valid:
        findings.append(
            {
                "title": "SSL/TLS Certificate Expired",
                "category": "Transport Security",
                "severity": "high",
                "description": "The SSL/TLS certificate has expired and is no longer valid. This can lead to browser warnings and potential security issues.",
                "evidence": f"Certificate valid until: {ssl_result.get('valid_until')}",
                "recommendation": "Renew or replace the SSL/TLS certificate immediately.",
            }
        )