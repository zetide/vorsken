# Run this in PowerShell at C:\dev\stacksecai-dev
Set-Content -Path 'rules\custom\api1_bola.yml' -Value 'rules:
  - id: api1-bola-fstring-sql
    patterns:
      - pattern: |
          $DB.execute(f"... {$ID} ...")
    message: >
      [API1:2023 - BOLA] SQL query built with f-string and user-supplied ID.
      Add ownership check before executing the query.
    languages: [python]
    severity: HIGH
    metadata:
      owasp: "API1:2023 - Broken Object Level Authorization"
      cwe: "CWE-639"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api2_broken_auth.yml' -Value 'rules:
  - id: api2-jwt-no-verify
    patterns:
      - pattern: |
          $TOKEN.split(".")[$IDX]
      - pattern-not-inside: |
          jwt.decode(...)
    message: >
      [API2:2023 - Broken Authentication] JWT token is manually decoded
      without signature verification. Use jwt.decode() with a secret key.
    languages: [python]
    severity: HIGH
    metadata:
      owasp: "API2:2023 - Broken Authentication"
      cwe: "CWE-345"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api3_mass_assignment.yml' -Value 'rules:
  - id: api3-sensitive-field-exposed
    patterns:
      - pattern: |
          "SELECT ... password_hash ... FROM ..."
    message: >
      [API3:2023 - Broken Object Property Level Authorization]
      password_hash or other sensitive fields are included in SELECT.
      Return only fields the caller is authorized to see.
    languages: [python]
    severity: MEDIUM
    metadata:
      owasp: "API3:2023 - Broken Object Property Level Authorization"
      cwe: "CWE-213"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api4_resource_limit.yml' -Value 'rules:
  - id: api4-fetchall-no-limit
    patterns:
      - pattern: |
          $DB.execute($QUERY).fetchall()
      - pattern-not: |
          $DB.execute($QUERY + " LIMIT $_").fetchall()
    message: >
      [API4:2023 - Unrestricted Resource Consumption] fetchall() with no
      LIMIT clause can return unbounded rows. Add LIMIT and pagination.
    languages: [python]
    severity: MEDIUM
    metadata:
      owasp: "API4:2023 - Unrestricted Resource Consumption"
      cwe: "CWE-770"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api5_func_authz.yml' -Value 'rules:
  - id: api5-login-check-only
    patterns:
      - pattern: |
          if not $USER.get("logged_in"):
              raise ...
      - pattern-not-inside: |
          if $USER.get("role") == ...:
              ...
    message: >
      [API5:2023 - Broken Function Level Authorization] Function checks only
      login state, not user role. Add role-based authorization.
    languages: [python]
    severity: HIGH
    metadata:
      owasp: "API5:2023 - Broken Function Level Authorization"
      cwe: "CWE-285"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api6_business_flow.yml' -Value 'rules:
  - id: api6-no-rate-limit-on-purchase
    patterns:
      - pattern: |
          def $FUNC($ITEM_ID, $QUANTITY, $USER_ID, $DB):
              $DB.execute("INSERT INTO orders ...")
      - pattern-not-inside: |
          @limiter.limit(...)
          def $FUNC(...):
              ...
    message: >
      [API6:2023 - Unrestricted Access to Sensitive Business Flows]
      Purchase or order endpoint has no rate limiting or bot protection.
    languages: [python]
    severity: MEDIUM
    metadata:
      owasp: "API6:2023 - Unrestricted Access to Sensitive Business Flows"
      cwe: "CWE-799"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api8_debug_mode.yml' -Value 'rules:
  - id: api8-debug-true
    pattern: |
      DEBUG = True
    message: >
      [API8:2023 - Security Misconfiguration] DEBUG=True must never be set
      in production code. Use environment variable to control this flag.
    languages: [python]
    severity: HIGH
    metadata:
      owasp: "API8:2023 - Security Misconfiguration"
      cwe: "CWE-94"

  - id: api8-hardcoded-secret-key
    patterns:
      - pattern: |
          SECRET_KEY = "$VALUE"
      - pattern-not: |
          SECRET_KEY = os.environ[...]
      - pattern-not: |
          SECRET_KEY = os.environ.get(...)
    message: >
      [API8:2023 - Security Misconfiguration] Hardcoded SECRET_KEY detected.
      Load from environment variable: os.environ[''SECRET_KEY'']
    languages: [python]
    severity: CRITICAL
    metadata:
      owasp: "API8:2023 - Security Misconfiguration"
      cwe: "CWE-798"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api9_inventory.yml' -Value 'rules:
  - id: api9-legacy-v1-endpoint
    patterns:
      - pattern: |
          @$APP.route("/api/v1/...")
          def $FUNC():
              ...
    message: >
      [API9:2023 - Improper Inventory Management] Legacy v1 API endpoint
      still active. Remove or formally deprecate old API versions.
    languages: [python]
    severity: MEDIUM
    metadata:
      owasp: "API9:2023 - Improper Inventory Management"
      cwe: "CWE-1059"
' -Encoding UTF8
Set-Content -Path 'rules\custom\api10_unsafe_api.yml' -Value 'rules:
  - id: api10-unvalidated-external-response
    patterns:
      - pattern: |
          $RESP = requests.get(...)
          $DATA = $RESP.json()
      - pattern-not: |
          $RESP = requests.get(...)
          $RESP.raise_for_status()
          $DATA = $RESP.json()
    message: >
      [API10:2023 - Unsafe Consumption of APIs] External API response used
      without status check. Call raise_for_status() and validate schema.
    languages: [python]
    severity: MEDIUM
    metadata:
      owasp: "API10:2023 - Unsafe Consumption of APIs"
      cwe: "CWE-20"
' -Encoding UTF8