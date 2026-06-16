# KAVACH — Workstream B
## Web Application Penetration Testing Findings
### OWASP Top 10 (2021) — Summary Table

Five vulnerabilities spanning OWASP Top 10 (2021) categories were identified, exploited, and remediated across DVWA and OWASP Juice Shop.

| Finding ID | Vulnerability Name | OWASP Category | Target App | Severity | Remediation |
|:---:|:---|:---|:---:|:---:|:---|
| **F-01** | Broken Access Control (Forged Review) | [A01:2021 — Broken Access Control](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A01%20Broken%20Access%20Control/A-01_Broken_Access_Control.md) | Juice Shop | 🟠 High | Server-side Session Check |
| **F-02** | Cryptographic Failures (XOR + AES-ECB) | [A02:2021 — Cryptographic Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A02%20Cryptographic%20Failures/) | DVWA | 🟠 High | AES-GCM + Secrets Vault |
| **F-03** | Injection (SQLi + XSS) | [A03:2021 — Injection](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A03%20Injection/1.SQL%20Injection/1.SQL%20Injection.md) | DVWA | 🔴 Critical | PDO / htmlspecialchars |
| **F-04** | Insecure Design (BasketId Manipulation) | [A04:2021 — Insecure Design](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A04%20Insecure%20Design/1.A04%20Insecure%20Design%20Findings.md) | Juice Shop | 🟡 Medium | Server-side Basket Derivation |
| **F-05** | Auth Failures (Weak Credentials) | [A07:2021 — Identification & Auth Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A07%20Identification%20and%20Authentication%20Failures/1.A07%20Identification%20and%20Authentication%20Failures%20Findings.md) | Juice Shop | 🟠 High | Rate Limiting + Strong Password Policy |
