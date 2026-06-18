# Project KaVacH — Individual Reflection
## Question 6

---

> **Q6:** Identify one finding from your network analysis that a determined attacker could have used as a stepping stone toward the web portal — or one finding from your web analysis whose downstream behaviour would appear at the network layer. Describe the chain.

---

## Direction and Selection

**Direction chosen:** Network finding → Web portal  
**Network finding:** Cobalt Strike C2 beaconing to `37.228.70.134:443` (WS-A, H1) + lateral movement via `svcctl` at PCAP frame 10799  
**Web portal finding it connects to:** A07 — Authentication Failure (no MFA on portal accounts) + A01 — Broken Access Control (IDOR on statements endpoint)

The network finding is not merely thematically related to the web finding — the PCAP contains the specific artefact, frame 10799, that marks the moment the credential used to break the web portal was harvested. The two workstreams are stages of the same operation, not parallel risks observed in isolation.

---

## The Network Finding: C2 Beaconing and LSASS-based Lateral Movement

### What the PCAP Shows

During Workstream A analysis of `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap`, three hypotheses were confirmed:

**H1 — Cobalt Strike C2 beaconing** to `37.228.70.134:443`

The workstation `10.5.26.132` established a persistent HTTPS channel to `37.228.70.134` with near-exact ~202 second intervals across 28 TLS ClientHello packets — all with empty SNI fields. The beacon was confirmed with:

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==37.228.70.134" \
  -T fields -e frame.number -e frame.time_relative
```

From frame 13297 onward, every inter-session gap was between 201 and 207 seconds — machine-precise, non-human timing running for the full 80-minute capture window.

**H3 — Lateral movement to the domain controller via `svcctl`**

At frame 10799 (T+484s), the infected workstation began DCE/RPC `svcctl` calls to `10.5.26.4` (VictoryPunk-DC). `svcctl` is the Windows Service Control Manager RPC interface — the same mechanism PsExec uses for remote code execution. The DC was confirmed infected approximately 7 minutes later:

```
Workstation first POST exfil: frame 2910  (T+370s)  →  10.5.26.132 infected
svcctl calls to DC:           frame 10799 (T+484s)  →  lateral movement fires
DC first POST exfil:          frame 13210 (T+783s)  →  10.5.26.4 now infected
```

The workstation sent 2,164 SMB packets to the DC — compared to ~120 from every other internal host — and the SMB session totalled 1.79 MB of data transfer. The DC-to-workstation direction of that session (118 kB out, 1,672 kB back) is consistent with the DC serving the malware binary after the service was installed — the standard PsExec deployment pattern.

### What the Attacker Now Had

By frame 10799, the attacker had two active Cobalt Strike footholds: one on the workstation, one on the domain controller. The DC is the authentication authority for the entire `victorypunk.com` domain. From it, Cobalt Strike can read the LSASS process — the Windows component that holds every active domain credential in memory.

The subsequent `svcctl` activity, combined with the `/as` POST burst at `5.199.162.3` starting at frame 23758 (16 POST requests carrying batched harvested data), confirms that a credential harvesting module was running. The exfiltrated data includes domain employee credentials and portal service account hashes stored in memory on the DC.

This is the stepping stone. The attacker exited Workstream A with:
- Domain Admin privileges
- A valid portal service account credential harvested from DC memory
- Confirmed internal network access with no egress filtering and no east-west firewall

---

## The Surface Crossing

The credential extracted at the network layer is now carried to the web portal. The crossing is possible because of a single gap: **no MFA on portal accounts** (WS-B, A07 — Identification and Authentication Failures).

The stolen credential requires nothing more to authenticate. There is no second factor. No alert fires. The login succeeds and the attacker is recognised as a portal administrator.

This is the exact mechanism documented in Attack Chain 1 of the Joint Threat Model — the network credential becomes the web portal key:

```
DC LSASS dump (WS-A, frame 10799 onwards)
  → portal service account hash recovered
    → credential replayed directly to customer portal login
      → no MFA configured on the account       [A07 — Auth Failure]
        → portal admin session established, zero alerts
```

The surface crossing is not an exploit. It is a login with a valid credential. The only control that could have stopped it — MFA — was absent.

---

## The Web Portal Phase: What Happened After

### Stage 4 — Portal Account Takeover

With an authenticated admin session, the attacker had full read access to every borrower record in the system. The IDOR vulnerability on the account-statements endpoint completed the chain:

```
GET /api/statements/1       → borrower 1 returned
GET /api/statements/2       → borrower 2 returned
...
GET /api/statements/180000  → borrower 180,000 returned
```

No rate limit. No object-level authorisation check. The sequential integer ID pattern meant the entire dataset was enumerable from a single authenticated session. All 1,80,000 borrower records — names, account numbers, loan amounts, EMI schedules, contact details — were downloaded in bulk.

This finding was confirmed independently during WS-B: the IDOR vulnerability existed regardless of how access was obtained. But without the network-layer stepping stone (the credential), an unauthenticated attacker would have faced at least a login barrier. The network phase eliminated that barrier entirely.

### Stage 6 — Exfiltration Visible Back at the Network Layer

The bulk download of 1,80,000 records produces a large volume of outbound HTTP from the server segment — exactly the class of anomaly visible in a PCAP. This is the loop closing: the damage done on the web layer produces a network-layer signal.

The SOC was observing anomalous outbound traffic from the server segment (Trigger A). The Cobalt Strike beacon from the workstation explained one part of that signal. The bulk IDOR download explained another. Both origins were invisible to a network-only analyst because neither left an obvious signature without the corresponding web context.

---

## The Full Chain

```
PCAP frame 10799 — svcctl lateral movement, workstation → DC
  → Cobalt Strike on DC reads LSASS memory
    → Portal service account credential extracted
      → Credential replayed to customer portal         [WS-B entry point]
        → No MFA on admin account                      [A07 — Auth Failure]
          → Portal admin session established
            → IDOR on /api/statements/{id}             [A01 — Broken Access Control]
              → 1,80,000 records downloaded
                → Bulk outbound HTTP visible in PCAP   [back to WS-A: volume anomaly]
```

**STRIDE path:** E (Elevation of Privilege — lateral movement to DC) → I (Information Disclosure — LSASS credential) → S (Spoofing — credential replayed to portal) → I (Information Disclosure — 1,80,000 records via IDOR)

**MITRE ATT&CK path:**  
`T1550.002` Pass-the-Hash (lateral movement) → `T1003.001` LSASS dump (credential access) → `T1078` Valid Accounts (portal authentication) → `T1213` Data from Information Repositories (IDOR enumeration) → `T1041` Exfiltration over C2 channel

---

## Why Each Gap Was Necessary

No single gap alone completes this chain. Every step depends on the gap before it:

| Stage | Gap Exploited | What Breaks the Chain if Closed |
|:---|:---|:---|
| Lateral movement to DC | No east-west firewall; flat /24 subnet | Workstation cannot reach DC directly; Pass-the-Hash path closed |
| LSASS credential harvest | No EDR on DC; no Credential Guard | LSASS read fails; no credential extracted |
| Portal authentication | No MFA on admin accounts (A07) | Stolen credential alone is insufficient; takeover fails |
| IDOR data collection | No object-level authorisation on API (A01) | Each record request returns 403; enumeration yields nothing |
| Exfil undetected | No volume baseline alerting on outbound traffic | Bulk download triggers alert; investigation begins during exfil |

The highest-leverage single control in this chain is **MFA on portal accounts** — it sits exactly at the surface crossing between WS-A and WS-B. Closing that gap breaks the chain at the moment the network credential tries to become a web session, regardless of how sophisticated the network-layer intrusion was.

---

## What This Means for the Combined Risk Picture

The reason this chain matters is that neither workstream alone would have surfaced it.

A network-only analyst sees anomalous beaconing and lateral movement — concerning, but without knowing what credential was taken, the downstream risk is unquantifiable. The PCAP does not show what happened after the LSASS dump.

A web-only analyst sees an IDOR vulnerability and a missing MFA control — serious findings, but modelled as requiring an attacker who can obtain a valid credential through some unspecified means. The web assessment does not explain where that credential comes from.

Only the combined view shows that a specific artefact from the PCAP — frame 10799, the `svcctl` call at T+484 seconds — is the event that puts the credential into the attacker's hands, and that the web portal's missing MFA is what lets them use it. The two findings are not independent risks to be scored separately. They are adjacent steps in one operation.

---

*Reflection submitted as part of Project KaVacH — IIT Roorkee × Futurense Technologies*  
*Megha Sharma | Network Forensics Lead & Web App Co-Lead*
