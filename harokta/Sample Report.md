

```
Analyzing HAR file: okta_test.har
Report will be written to: okta_test_okta_report.txt

=== BASIC SUMMARY ===
Total HTTP entries: 5
Okta-related entries: 3

=== SSO FLOW TRACE (STEP-BY-STEP) ===
Step 1: Browser → Okta /authorize (start of OAuth/OIDC login).
  Request: GET https://mycompany.okta.com/oauth2/default/v1/authorize?client_id=abc123&response_type=code&scope=openid
  Status:  302 Found
  Redirect Location: https://myapp.com/callback?code=fakecode123

Step 2: Backend/App → Okta /token (exchange code for tokens).
  Request: POST https://mycompany.okta.com/oauth2/default/v1/token
  Status:  401 Unauthorized

Step 3: Browser/App → Okta /authn (primary authentication).
  Request: GET https://mycompany.okta.com/api/v1/authn
  Status:  400 Bad Request


=== ALL REQUESTS (URL + STATUS) ===
200  https://example.com/
302  https://mycompany.okta.com/oauth2/default/v1/authorize?client_id=abc123&response_type=code&scope=openid
401  https://mycompany.okta.com/oauth2/default/v1/token
400  https://mycompany.okta.com/api/v1/authn
200  https://example.com/dashboard

=== OKTA-RELATED REQUESTS ===
302  GET     https://mycompany.okta.com/oauth2/default/v1/authorize?client_id=abc123&response_type=code&scope=openid
401  POST    https://mycompany.okta.com/oauth2/default/v1/token
400  GET     https://mycompany.okta.com/api/v1/authn

=== RESPONSES WITH STATUS >= 400 ===
401 Unauthorized         POST   https://mycompany.okta.com/oauth2/default/v1/token
400 Bad Request          GET    https://mycompany.okta.com/api/v1/authn

=== REDIRECTS (3xx) ===
302  https://mycompany.okta.com/oauth2/default/v1/authorize?client_id=abc123&response_type=code&scope=openid
     -> Location: https://myapp.com/callback?code=fakecode123

=== RESPONSES CONTAINING ERROR-LIKE CONTENT ===

--- POSSIBLE ERROR RESPONSE ---
URL: https://mycompany.okta.com/oauth2/default/v1/token
Status: 401
Matched terms: ['error', 'errorCode', 'error_description', 'E00000', 'E000001']
{"error": "invalid_client", "error_description": "Client authentication failed", "errorCode": "E0000011"}

--- POSSIBLE ERROR RESPONSE ---
URL: https://mycompany.okta.com/api/v1/authn
Status: 400
Matched terms: ['error', 'errorSummary', 'error_description', 'E00000']
{"errorSummary": "Authentication failed", "error": "E0000004", "error_description": "Invalid credentials"}

```