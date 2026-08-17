"""
Security Finding Engine Module

Converts results from HTTP checker, security header analyzer, and SSL certificate checker
into standardized security findings and calculates an overall security score.
"""

from typing import Dict, List, Any


def build_findings(
    http_result: Dict[str, Any],
    header_results: List[Dict[str, Any]],
    ssl_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Converts scan results into standardized security findings.

    Args:
        http_result (Dict[str, Any]): Result from check_website_url().
        header_results (List[Dict[str, Any]]): Result from analyze_security_headers().
        ssl_result (Dict[str, Any]): Result from check_ssl_certificate().

    Returns:
        List[Dict[str, Any]]: List of findings, each containing:
            - title (str): Short finding title
            - category (str): Finding category
            - severity (str): One of 'high', 'medium', 'low', 'info'
            - description (str): Detailed description
            - evidence (str): Evidence or data supporting the finding
            - recommendation (str): Recommended remediation

    Note: Findings are only generated for actual weaknesses detected.
    """
    findings: List[Dict[str, Any]] = []

    # Process HTTP/HTTPS findings
    _add_http_findings(findings, http_result)

    # Process security header findings
    _add_header_findings(findings, header_results)

    # Process SSL/TLS findings
    _add_ssl_findings(findings, ssl_result)

    return findings


def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculates a security score based on findings.

    Starts with 100 and subtracts:
    - High: 15 points
    - Medium: 8 points
    - Low: 3 points
    - Info: 0 points

    Args:
        findings (List[Dict[str, Any]]): List of findings from build_findings().

    Returns:
        int: Security score (0-100).
    """
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
    """
    Returns a rating string based on the security score.

    Args:
        score (int): Security score (0-100).

    Returns:
        str: One of 'Excellent', 'Good', 'Fair', 'Poor', 'Critical'.
    """
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
    """
    Adds HTTP/HTTPS related findings.

    Args:
        findings (List[Dict[str, Any]]): Findings list to append to.
        http_result (Dict[str, Any]): Result from check_website_url().
    """
    if not http_result:
        return

    final_url = http_result.get("final_url", "")

    # If final URL is HTTP (not HTTPS), create a finding
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
    """
    Adds security header findings.

    Args:
        findings (List[Dict[str, Any]]): Findings list to append to.
        header_results (List[Dict[str, Any]]): Result from analyze_security_headers().
    """
    if not header_results:
        return

    for header in header_results:
        # Only create findings for missing headers
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
    """
    Adds SSL/TLS certificate findings.

    Args:
        findings (List[Dict[str, Any]]): Findings list to append to.
        ssl_result (Dict[str, Any]): Result from check_ssl_certificate().
    """
    if not ssl_result:
        return

    error = ssl_result.get("error")
    is_valid = ssl_result.get("is_valid")
    is_https = ssl_result.get("is_https")
    certificate_present = ssl_result.get("certificate_present")

    if error:
        # Distinguish between inspection/connection errors and certificate/security errors
        error_lower = error.lower()

        # Inspection/connection errors - not security vulnerabilities
        is_inspection_error = any(
            keyword in error_lower
            for keyword in ["timeout", "dns", "connection", "invalid url", "could not extract"]
        )

        if is_inspection_error:
            # Do not create a finding for inspection/connection errors
            return

        # Certificate/security verification errors - treat as high severity
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

    # If certificate is valid, no vulnerability finding is created
