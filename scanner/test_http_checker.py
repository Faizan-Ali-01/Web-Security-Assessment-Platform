from pathlib import Path
import sys

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from scanner.http_checker import check_website_url


result = check_website_url("https://example.com")

print(f"URL: {result.get('url')}")
print(f"Final URL: {result.get('final_url')}")
print(f"Status Code: {result.get('status_code')}")
print(f"HTTPS Used: {result.get('https_used')}")
print(f"Redirected HTTP to HTTPS: {result.get('http_to_https_redirect')}")
print(f"Error: {result.get('error')}")
