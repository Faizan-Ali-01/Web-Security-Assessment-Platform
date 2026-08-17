"""
Information Exposure Checker Module

Analyzes HTTP response headers for information disclosure and fingerprinting risks.
Completely passive - does not make network requests.
"""

from typing import Dict, List, Any


def analyze_information_exposure(headers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyzes HTTP response headers for potentially revealing information.

    Args:
        headers (Dict[str, Any]): HTTP response headers dictionary from check_website_url().

    Returns:
        List[Dict[str, Any]]: List of observations for revealing headers, each containing:
            - header (str): The header name
            - value (str): The header value
            - type (str): Type of exposure (e.g., 'Server Version', 'Framework')
            - severity (str): Severity level ('low', 'info')
            - description (str): Description of the exposure
            - recommendation (str): Recommended remediation

    Note: Only returns observations for headers that are actually present.
    """
    observations: List[Dict[str, Any]] = []

    if not headers:
        return observations

    # Normalize headers dictionary (case-insensitive lookup)
    headers_lower = {key.lower(): (key, value) for key, value in headers.items()}

    # Define headers to inspect
    headers_to_check = {
        "server": {
            "type": "Server Version",
            "description": "Server version information disclosed, allowing attackers to identify specific server versions and target known vulnerabilities.",
            "recommendation": "Remove or mask server version information. Configure server to not reveal version details in responses.",
        },
        "x-powered-by": {
            "type": "Framework/Technology",
            "description": "Framework or technology version information disclosed, facilitating targeted attacks.",
            "recommendation": "Remove the X-Powered-By header. Configure framework to not expose version information.",
        },
        "x-aspnet-version": {
            "type": "Framework Version",
            "description": "ASP.NET version information disclosed, allowing attackers to identify the framework version and target known vulnerabilities.",
            "recommendation": "Disable ASP.NET version disclosure in web.config or application settings.",
        },
        "x-aspnetmvc-version": {
            "type": "Framework Version",
            "description": "ASP.NET MVC version information disclosed, allowing targeted attacks against specific framework versions.",
            "recommendation": "Remove X-AspNetMvc-Version header. Configure MVC framework to not expose version information.",
        },
        "x-generator": {
            "type": "Technology Stack",
            "description": "Development tool or generator information disclosed, revealing the technology stack used to build the site.",
            "recommendation": "Remove or mask the X-Generator header by configuring your content management system or build tools.",
        },
        "via": {
            "type": "Proxy/Intermediary",
            "description": "Proxy or intermediary information disclosed, revealing infrastructure details.",
            "recommendation": "Configure proxies and intermediaries to minimize information disclosure in Via headers.",
        },
    }

    # Check each header
    for header_lower, header_info in headers_to_check.items():
        if header_lower in headers_lower:
            original_header, value = headers_lower[header_lower]

            observations.append(
                {
                    "header": original_header,
                    "value": value,
                    "type": header_info["type"],
                    "severity": "low",
                    "description": header_info["description"],
                    "recommendation": header_info["recommendation"],
                }
            )

    return observations
