from __future__ import annotations

def analyze_security_headers(headers):
    if headers is None:
        headers = {}

    normalized_headers = {str(key).lower(): value for key, value in headers.items()}

    header_map = {
        "Strict-Transport-Security": {
            "severity_if_missing": "high",
            "recommendation": "Enable HSTS to enforce HTTPS and prevent downgrade attacks.",
        },
        "Content-Security-Policy": {
            "severity_if_missing": "high",
            "recommendation": "Define a restrictive CSP to reduce XSS and injection risks.",
        },
        "X-Content-Type-Options": {
            "severity_if_missing": "medium",
            "recommendation": "Set this to 'nosniff' to prevent MIME type confusion.",
        },
        "X-Frame-Options": {
            "severity_if_missing": "medium",
            "recommendation": "Prevent clickjacking by restricting framing of the site.",
        },
        "Referrer-Policy": {
            "severity_if_missing": "low",
            "recommendation": "Restrict referrer leakage to reduce information disclosure.",
        },
        "Permissions-Policy": {
            "severity_if_missing": "medium",
            "recommendation": "Limit browser features and APIs to the minimum required.",
        },
    }

    results = []

    for name, metadata in header_map.items():
        lookup_name = name.lower()
        value = normalized_headers.get(lookup_name)
        present = lookup_name in normalized_headers

        result = {
            "name": name,
            "present": present,
            "value": value if present else None,
            "severity": "none" if present else metadata["severity_if_missing"],
            "explanation": metadata["recommendation"] if not present else "Header is present and configured.",
        }

        results.append(result)

    return results
