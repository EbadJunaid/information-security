# Web Application Security Assessment Report
## DVWA (Damn Vulnerable Web Application) — University Assignment

---

**Assessor:**        [Ebad Junaid]  
**Student ID:**      [BSCS-22046]  
**Target:**          DVWA v1.10 — localhost (isolated lab environment)  
**Scope:**           SQL Injection · Command Injection · XSS (Reflected, Stored, DOM)  
**Security Levels Tested:** Low · Medium · High · Impossible (remediation reference)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Methodology](#2-methodology)
3. [Findings Overview](#3-findings-overview)
4. [Finding 1 — SQL Injection (Low)](#4-finding-1--sql-injection-low)
5. [Finding 2 — SQL Injection (Medium/High)](#5-finding-2--sql-injection-mediumhigh)
6. [Finding 3 — Command Injection](#6-finding-3--command-injection)
7. [Finding 4 — XSS Reflected](#7-finding-4--xss-reflected)
8. [Finding 5 — XSS Stored](#8-finding-5--xss-stored)
9. [Remediation Summary](#9-remediation-summary)
10. [References](#10-references)

---

## 1. Executive Summary

This report documents the findings of a controlled security assessment
performed against DVWA in an isolated local lab environment as part of
Information Security assignment. The assessment covered three primary
vulnerability classes: SQL Injection, Command Injection, and Cross-Site
Scripting (XSS).

All three vulnerability classes were confirmed across the Low security level.
Medium and High levels demonstrated progressively stronger — but still
insufficient — mitigations based on denylist filtering approaches. The
Impossible level in each module represents the industry-correct remediation
and serves as the recommended fix baseline.


---

## 2. Methodology

Testing followed a manual black-box approach within the DVWA interface,
supplemented by source code review of each security level's PHP backend
(available via the "View Source" button in DVWA).

**General process per module:**
1. Observe the default application behaviour with valid input.
2. Introduce boundary/edge-case input to probe for unexpected behaviour.
3. Review the PHP source to understand why the behaviour occurs.
4. Compare mitigations across security levels.
5. Document the Impossible-level fix as the recommended remediation.

**Ethical boundaries:** All testing was confined to the local DVWA container.
No external systems were targeted. No data was exfiltrated outside the lab
environment.

---

## 3. Findings Overview

| # | Vulnerability         | Location                       | Severity | Status              |
|---|-----------------------|--------------------------------|----------|---------------------|
| 1 | SQL Injection (Basic) | /vulnerabilities/sqli/         | Critical | Confirmed           |
| 2 | SQL Injection (Blind) | /vulnerabilities/sqli_blind/   | Critical | Confirmed (Low)     |
| 3 | Command Injection     | /vulnerabilities/exec/         | Critical | Confirmed (Low)     |
| 4 | XSS — Reflected       | /vulnerabilities/xss_r/        | High     | Confirmed (Low)     |
| 5 | XSS — Stored          | /vulnerabilities/xss_s/        | High     | Confirmed (Low)     |
| 6 | XSS — DOM             | /vulnerabilities/xss_d/        | High     | Confirmed (Low)     |

**Severity definitions used:**

- **Critical** — Immediate, direct impact: data exfiltration, remote code
  execution, or full authentication bypass achievable with minimal effort.
- **High** — Significant impact requiring user interaction or specific
  conditions; e.g. session hijacking via XSS.
- **Medium** — Limited impact in isolation but exploitable in combination
  with other weaknesses.
- **Low / Informational** — Best-practice violations with low direct impact.

---

## 4. Finding 1 — SQL Injection (Low)

### 4.1 Description

SQL Injection occurs when user-supplied input is concatenated directly into
a SQL query string. The database engine cannot distinguish between the
intended query structure and the injected content, allowing an attacker to
alter query logic or append additional queries.

### 4.2 Location & Parameter

- **URL:** `http://localhost:8080/vulnerabilities/sqli/`
- **Method:** GET
- **Parameter:** `id`

### 4.3 Vulnerable Code (Low Level)

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

The `$id` variable is taken directly from `$_REQUEST['id']` without
sanitisation or type validation and interpolated into the query string.

### 4.4 Proof of Concept (observed during manual testing)

**Test 1 — Boolean bypass:**
Input: `1' OR '1'='1`
Resulting query sent to DB:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
```

**Observed result:** Usernames and MD5-hashed passwords for all accounts were successfully extracted using automated UNION-based payloads via HexStrike-AI.

[DATABASE DUMP EXCERPT]
Table: users

| user    | password (MD5 Hash)              |
|---------|----------------------------------|
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337    | 8d18b14a60f9e9ad5b565b91bde4c30c |
| pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 |

**Test 2 — UNION-based data extraction:**
Input: `1' UNION SELECT user, password FROM users-- -`
Resulting query sent to DB:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'
UNION SELECT user, password FROM users-- -';
```
**Observed result:** Usernames and MD5-hashed passwords for all accounts
were returned in the response, including the admin account.

### 4.5 Impact

- Full authentication bypass
- Complete extraction of the users table including credential hashes
- MD5 hashes are weak and reversible via rainbow tables or offline cracking
- Potential for further exploitation: schema enumeration, file read/write
  (depending on DB user privileges)

### 4.6 CVSS Score (indicative)

CVSS v3.1 Base Score: **9.8 (Critical)**

### 4.7 Remediation

**Immediate fix — parameterized queries (prepared statements):**

PHP (PDO — matches DVWA Impossible level):
```php
$data = $db->prepare('SELECT first_name, last_name FROM users
                      WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
$data->execute();
```

Python equivalent (for reference):
```python
cursor.execute(
    "SELECT first_name, last_name FROM users WHERE user_id = ?",
    (user_id,)   # value passed separately — never interpolated
)
```

**Why this works:** The database engine receives the query structure and the
parameter value as separate protocol messages. It treats the parameter as
pure data regardless of its content — SQL metacharacters such as `'`, `--`,
and `UNION` have no syntactic effect.

**Secondary control — input validation:**
```php
if (is_numeric($id) && $id > 0) { /* proceed */ } else { die(); }
```

**Do not rely on:** `mysqli_real_escape_string()` alone (Medium/High levels).
Escaping is context-dependent and fragile — it fails in numeric contexts
where the value is not wrapped in quotes.

---

## 5. Finding 2 — SQL Injection (Medium/High)

### 5.1 Medium Level Analysis

**Code change:** Input is passed through `mysqli_real_escape_string()`.

```php
$id = ((isset($GLOBALS["___mysqli_ston"]) && ...) ?
    mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id) : "");
```

**Why it's still vulnerable:** The Medium level uses a POST form with a
dropdown (limiting UI-level input), but the underlying parameter can still
be sent manually via a crafted HTTP request. Additionally, if the query
used a numeric context (`WHERE user_id = $id` without quotes), escaping
provides no protection.

### 5.2 High Level Analysis

**Code change:** Adds `LIMIT 1` and uses `mysqli_real_escape_string()`.
Input is passed via a second window/session to complicate automated testing.

**Why it's still vulnerable:** The LIMIT clause prevents UNION attacks from
returning multiple rows, but time-based blind injection (e.g. `SLEEP()` /
`BENCHMARK()`) does not depend on returned rows and remains viable.
Additionally, denylist escaping does not address all injection vectors.

### 5.3 Key Lesson

Denylist approaches (escaping, LIMIT) reduce attack surface but cannot
eliminate the vulnerability class. Only parameterized queries address the
root cause.

---

## 6. Finding 3 — Command Injection

### 6.1 Description

Command Injection occurs when user input is passed to a system shell
without sanitisation. The shell interprets metacharacters in the input as
command separators, allowing additional OS commands to be executed with the
privileges of the web server process.

### 6.2 Location & Parameter

- **URL:** `http://localhost:8080/vulnerabilities/exec/`
- **Method:** POST
- **Parameter:** `ip`

### 6.3 Vulnerable Code (Low Level)

```php
$cmd = shell_exec('ping -c 4 ' . $target);
echo '<pre>' . $cmd . '</pre>';
```

### 6.4 Level-by-Level Mitigation Analysis

| Level      | Mechanism                           | Bypass exists?  |
|------------|-------------------------------------|-----------------|
| Low        | None                                | Yes — any metachar |
| Medium     | Strips `&&` and `;`                 | Yes — use `\|` or `\|\|` |
| High       | Strips broader set of metacharacters| Partial — implementation-dependent |
| Impossible | Allowlist: validates IPv4 format before shell call | No |

### 6.5 Root Cause

Passing user input to `shell_exec()`, `system()`, `exec()`, or `passthru()`
with `shell=True` (Python) / without shell escaping (PHP) creates a direct
injection path. The shell interprets the full string, including any
metacharacters the user supplies.

### 6.6 Remediation

**Correct fix — avoid the shell entirely:**

```python
# Python — safe pattern
import subprocess
args = ["ping", "-c", "1", validated_ip]   # list form, no shell
subprocess.run(args, shell=False)          # shell=False is the default
```

```php
# PHP — if shell is unavoidable, use escapeshellarg()
$cmd = 'ping -c 4 ' . escapeshellarg($target);
# Better: validate first, then construct command without user input in metachar positions
```

**Preferred fix — allowlist validation before any system call:**

```python
import re, subprocess
pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
if re.match(pattern, user_input) and all(
    0 <= int(o) <= 255 for o in user_input.split(".")
):
    subprocess.run(["ping", "-c", "1", user_input], shell=False)
else:
    raise ValueError("Invalid IP address")
```

---

## 7. Finding 4 — XSS Reflected

### 7.1 Description

Reflected XSS occurs when user input is echoed back in an HTTP response
without encoding, allowing an attacker to inject script that executes in
the victim's browser. The payload travels in the URL/request and is
"reflected" in the response — it is not stored.

### 7.2 Location & Parameter

- **URL:** `http://localhost:8080/vulnerabilities/xss_r/`
- **Method:** GET
- **Parameter:** `name`

### 7.3 Vulnerable Code (Low Level)

```php
echo '<pre>Hello ' . $_GET['name'] . '</pre>';
```

Input is written directly into the HTML response without HTML encoding.

### 7.4 Impact

- Session hijacking: `document.cookie` theft via injected script
- Credential phishing via DOM manipulation
- Keylogging, form data interception
- Delivery vehicle for drive-by malware (in combination with other flaws)

### 7.5 Remediation

**Output encoding** is the primary control. Encode all user-supplied data
for the context in which it is rendered:

```php
# PHP — HTML context
echo '<pre>Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</pre>';
```

```python
# Python — HTML context (using standard library)
import html
safe_output = html.escape(user_input)
```

**Context matters:** The encoding function differs by output context:

| Output context           | Required encoding                    |
|--------------------------|--------------------------------------|
| HTML body/attribute      | `htmlspecialchars()` / `html.escape()`|
| JavaScript variable      | JSON encode + `htmlspecialchars()`   |
| URL parameter            | `urlencode()` / `urllib.parse.quote()`|
| CSS value                | CSS hex encoding                     |

**Content Security Policy (secondary control):**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
CSP limits the impact of XSS by restricting which scripts the browser will
execute, but it does not replace output encoding — it is a defence-in-depth
layer.

---

## 8. Finding 5 — XSS Stored

### 8.1 Description

Stored XSS differs from reflected XSS in that the malicious payload is
persisted in the application's database and served to every user who views
the affected page. This multiplies the potential victim count and enables
persistent session hijacking without requiring the victim to click a
crafted link.

### 8.2 Location & Parameter

- **URL:** `http://localhost:8080/vulnerabilities/xss_s/`
- **Method:** POST
- **Parameters:** `txtName`, `mtxMessage`

### 8.3 Vulnerable Code (Low Level)

```php
// Stored without sanitisation
$message = stripslashes($_POST['mtxMessage']);  // stripslashes only — not HTML-safe
$name    = stripslashes($_POST['txtName']);

$query = "INSERT INTO guestbook (comment, name) VALUES ('$message', '$name');";
// Note: also vulnerable to SQL injection at Low level
```

```php
// Rendered without encoding
echo '<td>' . $row['comment'] . '</td>';
```

### 8.4 Remediation

The same output encoding principle applies, but must be applied at
**both** the input layer (before storage) and the output layer (before
rendering). Relying solely on input sanitisation is insufficient because:

1. Sanitisation logic may be bypassed or updated inconsistently.
2. Data from other sources (APIs, imports) may bypass the input layer.
3. The output layer is always the definitive trust boundary.

```php
// On output — always encode for context
echo '<td>' . htmlspecialchars($row['comment'], ENT_QUOTES, 'UTF-8') . '</td>';

// On input — optional additional layer (store clean or store raw + encode on output)
$message = htmlspecialchars($_POST['mtxMessage'], ENT_QUOTES, 'UTF-8');
```

---

## 9. Remediation Summary

| Vulnerability    | Root Cause                        | Correct Fix                                  | Do Not Rely On                    |
|------------------|-----------------------------------|----------------------------------------------|-----------------------------------|
| SQL Injection    | String interpolation into queries | Parameterized queries + type validation       | `mysqli_real_escape_string()`     |
| Command Injection| User input passed to shell        | Allowlist validation + `shell=False` / list args | Metacharacter denylist stripping |
| XSS (all types)  | Unencoded output to browser       | Context-appropriate output encoding + CSP    | Input filtering / `strip_tags()`  |

### General Principles

1. **Validate on input, encode on output.** These are complementary controls,
   not alternatives.
2. **Allowlists over denylists.** Define what is permitted; reject everything
   else. Denylists miss edge cases and are defeated by encoding variations.
3. **Principle of least privilege.** Database accounts used by web apps should
   not have DBA privileges. The web server process should not run as root.
4. **Defence in depth.** No single control is sufficient. Layer validation,
   parameterization, encoding, CSP, WAF, and monitoring.
5. **Use frameworks.** Modern ORM and templating frameworks apply safe patterns
   by default. Raw query building and raw HTML generation are antipatterns.

---

## 10. References

- OWASP Top Ten 2021: https://owasp.org/Top10/
- OWASP SQL Injection Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP OS Command Injection Defense Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- OWASP XSS Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- DVWA Source Repository: https://github.com/digininja/DVWA
- CWE-89 (SQL Injection): https://cwe.mitre.org/data/definitions/89.html
- CWE-78 (OS Command Injection): https://cwe.mitre.org/data/definitions/78.html
- CWE-79 (XSS): https://cwe.mitre.org/data/definitions/79.html

---

*Report prepared for academic assessment purposes.
All testing was conducted in an isolated, authorised lab environment.*
