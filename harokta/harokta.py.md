
```python

#!/usr/bin/env python3
"""
Analyze a HAR file for Okta SSO-related errors using Haralyzer,
decode JWTs using PyJWT, trace the SSO flow step-by-step,
and write a report to a text file.

Usage:
    python analyze_okta_har.py /path/to/file.har
"""

import sys
import os
import json
import re
from urllib.parse import urlparse, parse_qs, parse_qsl

from haralyzer import HarParser
import jwt  # PyJWT


def write_line(report_lines, text=""):
    report_lines.append(text)
    print(text)


def load_har(har_file_path: str) -> HarParser:
    with open(har_file_path, "r", encoding="utf-8") as f:
        har_data = json.load(f)
    return HarParser(har_data)


def is_okta_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return (
        "okta.com" in host
        or "okta-emea.com" in host
        or "oktapreview.com" in host
    )


# ===== JWT HELPERS ===========================================================

def decode_jwt_if_present(token: str, report_lines):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        header = jwt.get_unverified_header(token)

        write_line(report_lines, "\n--- JWT FOUND & DECODED ---")
        write_line(report_lines, f"Header:  {json.dumps(header, indent=2)}")
        write_line(report_lines, f"Payload: {json.dumps(decoded, indent=2)}")
        write_line(report_lines)
    except Exception as e:
        write_line(report_lines, f"\nJWT detected but could not decode: {e}\n")


def find_jwts_in_text(text: str, report_lines):
    """Search for JWT-like strings in any content."""
    if not text:
        return

    jwt_pattern = r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    matches = re.findall(jwt_pattern, text)

    for token in matches:
        decode_jwt_if_present(token, report_lines)


def find_jwt_in_url(url: str, report_lines):
    parsed = urlparse(url)

    # Query parameters
    params = dict(parse_qsl(parsed.query))
    for _, value in params.items():
        if value.count(".") == 2:
            decode_jwt_if_present(value, report_lines)

    # Fragment parameters (#id_token=..., etc.)
    fragment_params = dict(parse_qsl(parsed.fragment))
    for _, value in fragment_params.items():
        if value.count(".") == 2:
            decode_jwt_if_present(value, report_lines)


# ===== BASIC SUMMARY =========================================================

def print_basic_summary(entries, report_lines):
    write_line(report_lines, "=== BASIC SUMMARY ===")
    write_line(report_lines, f"Total HTTP entries: {len(entries)}")
    okta_entries = [e for e in entries if is_okta_url(e['request']['url'])]
    write_line(report_lines, f"Okta-related entries: {len(okta_entries)}")
    write_line(report_lines)


def list_all_requests(entries, report_lines):
    write_line(report_lines, "=== ALL REQUESTS (URL + STATUS) ===")
    for e in entries:
        url = e['request']['url']
        status = e['response']['status']
        write_line(report_lines, f"{status:3}  {url}")
        find_jwt_in_url(url, report_lines)
    write_line(report_lines)


def list_okta_requests(entries, report_lines):
    write_line(report_lines, "=== OKTA-RELATED REQUESTS ===")
    okta_entries = [e for e in entries if is_okta_url(e['request']['url'])]

    if not okta_entries:
        write_line(report_lines, "No Okta URLs found.\n")
        return

    for e in okta_entries:
        req = e['request']
        res = e['response']
        url = req['url']
        method = req['method']
        status = res['status']
        write_line(report_lines, f"{status:3}  {method:6}  {url}")
        find_jwt_in_url(url, report_lines)
    write_line(report_lines)


def list_error_statuses(entries, report_lines, min_status=400):
    write_line(report_lines, f"=== RESPONSES WITH STATUS >= {min_status} ===")
    errors = [e for e in entries if e['response']['status'] >= min_status]

    if not errors:
        write_line(report_lines, "No error HTTP statuses found.\n")
        return

    for e in errors:
        req = e['request']
        res = e['response']
        url = req['url']
        method = req['method']
        status = res['status']
        status_text = res.get('statusText', '')
        write_line(report_lines, f"{status:3} {status_text:20} {method:6} {url}")
    write_line(report_lines)


def list_redirects(entries, report_lines):
    write_line(report_lines, "=== REDIRECTS (3xx) ===")
    redirects = [e for e in entries if 300 <= e['response']['status'] < 400]

    if not redirects:
        write_line(report_lines, "No redirects found.\n")
        return

    for e in redirects:
        res = e['response']
        req = e['request']
        url = req['url']
        status = res['status']

        location_header = next(
            (h.get("value") for h in res.get("headers", []) if h.get("name", "").lower() == "location"),
            None,
        )

        write_line(report_lines, f"{status:3}  {url}")
        if location_header:
            write_line(report_lines, f"     -> Location: {location_header}")
            find_jwt_in_url(location_header, report_lines)
    write_line(report_lines)


# ===== ERROR CONTENT SEARCH ==================================================

def search_for_error_content(entries, report_lines):
    terms = [
        "error", "errorCode", "errorSummary",
        "error_description", "access_denied",
        "E00000", "E000001"
    ]

    write_line(report_lines, "=== RESPONSES CONTAINING ERROR-LIKE CONTENT ===")
    found_any = False

    for e in entries:
        res = e['response']
        content = res.get('content', {})
        text = content.get('text', "")

        if not text:
            continue

        find_jwts_in_text(text, report_lines)

        text_lower = text.lower()
        matched = [t for t in terms if t.lower() in text_lower]

        if matched:
            found_any = True
            url = e['request']['url']
            status = res['status']

            write_line(report_lines, "\n--- POSSIBLE ERROR RESPONSE ---")
            write_line(report_lines, f"URL: {url}")
            write_line(report_lines, f"Status: {status}")
            write_line(report_lines, f"Matched terms: {matched}")
            write_line(report_lines, text[:500])
            if len(text) > 500:
                write_line(report_lines, "... [truncated]")

    if not found_any:
        write_line(report_lines, "No responses containing error terms found.\n")


# ===== SSO FLOW TRACE ========================================================

def classify_sso_step(entry):
    req = entry["request"]
    res = entry["response"]
    url = req["url"]
    status = res["status"]

    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()

    if is_okta_url(url) and "authorize" in path:
        return "Browser → Okta /authorize (start of OAuth/OIDC login)."
    if is_okta_url(url) and "token" in path:
        return "Backend/App → Okta /token (exchange code for tokens)."
    if is_okta_url(url) and "/api/v1/authn" in path:
        return "Browser/App → Okta /authn (primary authentication)."

    if "sso/saml" in path or "saml2" in path:
        if is_okta_url(url):
            return "Browser → Okta SAML endpoint (IdP SSO)."
        else:
            return "Browser → App SAML endpoint (SP ACS)."

    if status in (301, 302, 303, 307, 308):
        location_header = next(
            (h.get("value") for h in res.get("headers", []) if h.get("name", "").lower() == "location"),
            ""
        ).lower()

        if "code=" in location_header or "id_token=" in location_header:
            return "Redirect with authorization code/id_token back to application."
        if "samlresponse=" in location_header:
            return "Redirect carrying SAMLResponse back to application."

    if "code=" in query or "id_token=" in query:
        return "App receives OAuth code/id_token at redirect URI."

    if "samlresponse=" in query:
        return "App receives SAMLResponse at ACS endpoint."

    return None


def trace_sso_flow(entries, report_lines):
    write_line(report_lines, "=== SSO FLOW TRACE (STEP-BY-STEP) ===")

    step = 1
    for entry in entries:
        desc = classify_sso_step(entry)
        if not desc:
            continue

        req = entry["request"]
        res = entry["response"]
        url = req["url"]
        method = req["method"]
        status = res["status"]
        status_text = res.get("statusText", "")

        write_line(report_lines, f"Step {step}: {desc}")
        write_line(report_lines, f"  Request: {method} {url}")
        write_line(report_lines, f"  Status:  {status} {status_text}")

        if status in (301, 302, 303, 307, 308):
            location_header = next(
                (h.get("value") for h in res.get("headers", []) if h.get("name", "").lower() == "location"),
                None,
            )
            if location_header:
                write_line(report_lines, f"  Redirect Location: {location_header}")

        step += 1
        write_line(report_lines)

    if step == 1:
        write_line(report_lines, "No obvious SSO flow detected (no Okta /authorize, /token, SAML, or similar endpoints found).")
    write_line(report_lines)


# ===== MAIN ==================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_okta_har.py /path/to/file.har")
        sys.exit(1)

    har_file_path = sys.argv[1]

    base, _ = os.path.splitext(har_file_path)
    report_file_path = base + "_okta_report.txt"

    report_lines = []
    write_line(report_lines, f"Analyzing HAR file: {har_file_path}")
    write_line(report_lines, f"Report will be written to: {report_file_path}\n")

    try:
        har_parser = load_har(har_file_path)
    except Exception as e:
        write_line(report_lines, f"Failed to load HAR file: {e}")
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        sys.exit(1)

    # ✅ FIX: Haralyzer may expose either full HAR or already the inner "log" object
    har_root = har_parser.har_data
    log_obj = har_root.get("log", har_root)
    entries = log_obj.get("entries", [])
    if not entries:
        raise KeyError(f"No 'entries' found. Top-level keys: {list(har_root.keys())}, log keys: {list(log_obj.keys())}")

    # Sections
    print_basic_summary(entries, report_lines)
    trace_sso_flow(entries, report_lines)
    list_all_requests(entries, report_lines)
    list_okta_requests(entries, report_lines)
    list_error_statuses(entries, report_lines)
    list_redirects(entries, report_lines)
    search_for_error_content(entries, report_lines)

    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"\nReport written to: {report_file_path}")


if __name__ == "__main__":
    main()