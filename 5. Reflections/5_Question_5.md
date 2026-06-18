# Project KaVacH — Individual Reflection
## Question 5

---

> **Q5:** Where in the engagement did an LLM mislead you. Quote or paraphrase the specific output, explain how you noticed it was wrong, and describe what you did instead.

---

## Context

During the Reflected XSS assessment (Workstream B, DVWA `http://localhost:8081/vulnerabilities/xss_r/`), the team used an LLM to help generate filter bypass payloads for the DVWA medium security level. The LLM's output was structurally correct — but one payload it recommended contained a subtle assumption about how the DVWA medium filter worked that was wrong in practice, and following it without verification would have produced an incomplete finding in the report.

---

## The Moment: Filter Bypass Payload Advice

### What I Asked

After the basic `<script>alert('XSS');</script>` payload was stripped by DVWA medium security, I asked the LLM (Claude, Sonnet 4.6):

> *"For DVWA medium security XSS, my payload `<script>alert('XSS');</script>` is being filtered. The filter is using str_replace in PHP. Give me bypass payloads and explain why each one works."*

### What the LLM Said

The LLM gave four payloads. Three were accurate. The fourth was the problem. Paraphrased closely:

> *"Bypass 4 — Event Handler, No Tag Name (beats case-insensitive filter):*
> *Payload: `<body onload=alert(1)>`*
> *Why it works: Even a case-insensitive filter that strips all `<script>` variants cannot enumerate every HTML element. A `<body>` tag with `onload` triggers on page load without any script tag — the filter has no coverage over this vector."*

The LLM then stated this payload would work against **both** a case-sensitive and a case-insensitive `str_replace` filter — and implied that because it uses no `<script>` tag at all, it was the "safest" bypass to document as the most business-relevant finding.

### Why That Was Wrong

The LLM's explanation was technically accurate in the abstract — `<body onload=alert(1)>` does bypass a `<script>`-only filter. That part is correct.

The mistake was in what it implied about DVWA's actual medium-level filter. The DVWA medium `xss_r` source is:

```php
// medium.php
$name = str_replace( '<script>', '', $_GET[ 'name' ] );
echo '<pre>Hello ' . $name . '</pre>';
```

The filter only strips the literal string `<script>` — which means every alternative tag (`<img>`, `<svg>`, `<body>`) passes through completely untouched, not just `<body onload>`. The LLM had framed `<body onload>` as the *best* bypass — the one that defeats even a case-insensitive filter — but in doing so it implicitly positioned it as the hardest-to-defend vector, which shaped my first draft of the Root Cause section incorrectly.

I originally wrote in the finding draft:

> *"The `<body onload>` payload is the most significant bypass because it defeats both case-sensitive and case-insensitive variants of the filter."*

This was wrong for this specific finding. The real root cause at medium security is not that `<body onload>` is a uniquely powerful technique — it is that `str_replace` is architecturally broken as a security control regardless of which tag you use. `<img onerror=alert(1)>` and `<svg onload=alert(1)>` work for exactly the same reason as `<body onload=alert(1)>`. They are all equivalent bypasses. Singling out `<body onload>` as the headline finding would have misrepresented the severity and misled a reviewer into thinking a targeted fix (blocking `<body>` tags) would close the issue.

---

## How I Noticed It Was Wrong

**Step 1 — I tested all four payloads against the actual DVWA instance.**

Running each one in the browser at `security=medium`:

| Payload | Result |
|:---|:---|
| `<SCRIPT>alert('XSS');</SCRIPT>` | ✅ Alert fired |
| `<scr<script>ipt>alert('XSS');</script>` | ✅ Alert fired |
| `<img src=x onerror=alert(1)>` | ✅ Alert fired |
| `<body onload=alert(1)>` | ✅ Alert fired |
| `<svg onload=alert(1)>` | ✅ Alert fired |

All five worked. There was no difference between them at this security level.

**Step 2 — I read the actual DVWA medium source PHP.**

Viewing source at `/vulnerabilities/xss_r/source/medium.php` confirmed:

```php
$name = str_replace( '<script>', '', $_GET[ 'name' ] );
```

Only one string is being stripped: the exact lowercase `<script>` tag. The filter has zero coverage for anything else. `<body onload>` was not uniquely privileged — it was merely one of dozens of equally valid bypasses.

**Step 3 — I recognised the framing problem in my draft.**

When I re-read what I had written ("most significant bypass"), I realised I had absorbed the LLM's ranking without questioning it. The LLM had structured its response from "case-sensitive bypasses" through to "case-insensitive bypasses" — with `<body onload>` positioned at the end as the strongest. That ordering made sense as a general taxonomy of XSS bypass escalation, but it did not map to this specific filter, which was only ever case-sensitive and only ever targeted `<script>`. There was no escalation here — all non-script-tag payloads were equal.

---

## What I Did Instead

**Ran all payloads manually before writing any finding claim.**

The corrected Root Cause section was rewritten to reflect what was actually true:

```
The DVWA medium filter uses str_replace('<script>', '', $input) — a single-pass,
case-sensitive strip of one specific string. This is not a security control. Any
payload that does not contain the literal string <script> passes through unmodified.
The bypass is not a technique — it is a consequence of the filter's architectural
failure. Fixing the specific payloads that worked here would not remediate the
vulnerability.
```

**Changed the business-relevant payload in the report.**

The `<img src=x onerror=alert(1)>` payload was selected as the representative bypass in the finding — not `<body onload>` — because the `onerror` handler on an invalid image source is a more realistic delivery vector for a financial portal (image tags appear in product listings, profile pages, and content fields), and because it better illustrates the class of bypass rather than a single edge-case tag.

**Re-anchored the remediation recommendation.**

Because the root cause is the filter architecture — not any specific tag — the remediation in the finding points to `htmlspecialchars()` output encoding as the fix, not an expanded blocklist. The LLM's framing had momentarily pulled the recommendation toward "also block `<body>` and `<svg>` tags," which is exactly the wrong direction and would have reproduced the same architectural mistake at a wider scope.

---

## The Broader Takeaway

The LLM's payload list was accurate. Every bypass it named was valid. The error was in the explanatory framing — specifically, it ranked `<body onload>` as uniquely powerful in a way that was true in general XSS bypass taxonomy but false for this specific filter. This kind of error is harder to catch than a hallucination because the underlying technical claim is correct; only its relevance to the specific context is wrong.

The fix was straightforward: verify every payload claim against the actual running system before writing it into a finding. The test environment exists precisely for this. An LLM answering a general question gives a general answer — the specific answer comes from the specific application.

---

*Reflection submitted as part of Project KaVacH — IIT Roorkee × Futurense Technologies*  
*Megha Sharma | Network Forensics Lead & Web App Co-Lead*
