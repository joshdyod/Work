# harokta Okta SSO HAR Analyzer

harokta is a Python command-line tool for analyzing browser HAR files to diagnose
Okta SSO (OIDC / OAuth / SAML) authentication issues.

It parses a HAR file and produces a human-readable report that includes:

- Step-by-step SSO flow tracing
- Okta endpoint detection
- Redirect chain analysis
- HTTP error detection
- JWT discovery and decoding (header + payload, no signature verification)
- Error message extraction from responses

---

## Requirements

Python libraries:
- haralyzer
- PyJWT

---

## Installation 

macOS uses a system-managed Python. You MUST use a virtual environment.

1. Install dependencies:

    pip install haralyzer PyJWT

---

## Capturing a HAR File

Chrome / Edge:

1. Open DevTools → Network
2. Check "Preserve log"
3. Perform the SSO login
4. Right-click inside the request list
5. Select "Save all as HAR with content"

---

## Usage

Run the script with a HAR file:

    python3 harokta.py path/to/login_attempt.har

Example:

    python3 harokta.py fake_okta_test.har

This generates a report file:

    fake_okta_test_okta_report.txt

---

## Report Contents

### Basic Summary

Shows:
- Total HTTP requests
- How many requests were Okta-related

---

### SSO Flow Trace (Step-by-Step)

Example:

    Step 1: Browser → Okta /authorize
    Step 2: Redirect with authorization code back to application
    Step 3: Backend → Okta /token

This helps identify where the SSO flow breaks.

---

### Okta Requests

Lists all requests to:
- /authorize
- /token
- /api/v1/authn
- SAML endpoints

---

### Redirect Analysis

Shows all HTTP 3xx redirects and their Location headers.

Useful for:
- Redirect loops
- Misconfigured callback URLs

---

### Error Detection

Highlights:
- HTTP 4xx / 5xx responses
- Okta error codes (E0000011, access_denied, etc.)
- JSON error bodies

---

### JWT Detection and Decoding

Automatically finds JWTs in:
- URLs
- Redirects
- Response bodies

Decodes:
- JWT header
- JWT payload

NOTE: JWT signatures are NOT verified. This is intentional and safe for debugging.

