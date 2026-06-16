# A.2 · Triage Pass — Wireshark GUI Guide
### Project KAVACH | Workstream A | Trickbot + Cobalt Strike PCAP

> **Analyst Role:** Network Traffic Analyst | Tool: Wireshark (GUI)
> **Document Version:** v1.0 | Sprint 2–3

---

## What is a Triage Pass?

In network forensics, a **triage pass** is the first structured look at a packet capture (PCAP) file. The goal is **not** to find the attack immediately — the goal is to **characterise what is normal first**, so that anything abnormal stands out clearly.

> **Clue A (from the brief):** *"Baseline first, anomaly second. Triage is not 'find the suspicious'; it is 'characterise the normal'. An anomaly only has meaning against a baseline."*

A triage pass produces a **high-level inventory** covering six parameters:

| # | Parameter | What it answers |
|---|-----------|-----------------|
| 1 | Protocol Distribution | What languages is the network speaking? |
| 2 | Endpoints | Who is on the network? |
| 3 | Conversations | Who is talking to whom? |
| 4 | Top Talkers | Who is doing the most talking? |
| 5 | Time Bounds | When did the capture start and end? |
| 6 | Anomalous Bursts | Were there sudden, unexplained spikes? |

---

## A.1 · PCAP Details

| Field | Value |
|-------|-------|
| **File Name** | `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap` |
| **File Size** | 17 MB |
| **Format** | Wireshark/tcpdump — `.pcap` |
| **Total Packets** | 26,644 |
| **Time Span** | 4,809.707 seconds (~80 minutes) |
| **Hash (SHA-256)** | `fee3f9a285ab295821a7452a80cfaab25b8ccc60ad39052547ec67c8c3c9ca1e` |
| **Hash (SHA-1)** | `a177be80b43d65c46c9930793be1ac76f32dbb32` |
| **Source** | Malware-Traffic-Analysis.net (public corpus) |
| **Scenario Relevance** | Contains Trickbot malware C2 beaconing and Cobalt Strike lateral movement — a direct analogue for the Meridian FinServe east-west + outbound anomaly described in Trigger A |

<!-- IMAGE-01: Wireshark → Statistics → Capture File Properties showing file name, packet count, start time, end time, and duration -->
<p align="center">
  <img src="./Evidences/1.png" width="75%" alt="PCAP File Properties - File Name, Packet Count, Start Time, End Time and Duration" />
</p>
<p align="center"><em>Figure 1: Wireshark Statistics – Capture File Properties showing File Name, Packet Count, Start Time, End Time and Duration</em></p>

---

## Section 1 · Protocol Distribution

### What is Protocol Distribution?

Protocol distribution shows which network protocols are present in the capture and how much of the traffic each one accounts for — by packet count and by bytes. This is the **first thing a forensic analyst checks** because the protocol mix tells you what kind of activity is happening and immediately flags anything unusual.

For a normal corporate NBFC environment, you'd expect mostly HTTPS/TLS, DNS, and some SMB. Seeing large volumes of HTTP (unencrypted), unusual SMB spikes, or unexpected LDAP traffic is a red flag.

### Steps — Protocol Hierarchy

- Open the `.pcap` file in Wireshark
- Go to **Statistics → Protocol Hierarchy**
- Wireshark displays a tree showing:
  - All protocol names (Ethernet, IP, TCP, UDP, HTTP, DNS, TLS, SMB, etc.)
  - Percentage of packets per protocol
  - Total packet count per protocol
  - Total bytes and percentage of bytes per protocol
- Look for protocols that are **unexpectedly high in bytes** relative to packet count — this often indicates large payload transfers (e.g. data exfiltration via HTTP)
- Pay particular attention to **HTTP carrying disproportionate bytes** vs its packet count — in this PCAP, HTTP was only 1.08% of packets but carried 41.2% of bytes

<!-- IMAGE-02: Wireshark → Statistics → Protocol Hierarchy — full protocol tree with packet/byte percentages -->
<p align="center">
  <img src="./Evidences/2.png" width="75%" alt="Protocol Hierarchy - Full Protocol Tree with Packet/Byte Percentages" />
</p>
<p align="center"><em>Figure 2: Wireshark Statistics – Protocol Hierarchy full protocol tree with Packet/Byte Percentages</em></p>

<!-- IMAGE-03: Protocol Hierarchy — zoomed in on anomalous HTTP row showing byte vs packet disproportion -->
<p align="center">
  <img src="./Evidences/3.png" width="75%" alt="Protocol Hierarchy - HTTP Anomaly showing Byte vs Packet Disproportion" />
</p>
<p align="center"><em>Figure 3: Wireshark Protocol Hierarchy – Zoomed in on anomalous HTTP row showing Byte vs Packet Disproportion</em></p>

---

## Section 2 · Endpoints

### What are Endpoints?

An endpoint is any device on the network that is **sending or receiving traffic** — identified by its IP address (Layer 3), MAC address (Layer 2), or IP:Port pair (Layer 4). Mapping endpoints gives you a picture of **who is on the network** during the capture window.

In a forensic triage, the endpoint list helps you:
- Identify the victim machine(s)
- Identify external IPs the victim communicated with
- Spot unexpected devices on internal segments
- Find IPs with unusually high outbound bytes (potential exfiltration source)

### Steps — Endpoints

- Go to **Statistics → Endpoints**
- You will see tabs for: **Ethernet** (MAC), **IPv4**, **IPv6**, **TCP**, **UDP**
- Click the **IPv4** tab for IP-level analysis
- Click the **Bytes** column header to sort by total traffic — the top entries are your highest-activity hosts
- Click the **Tx Bytes** column to see who is *sending* the most data outbound
- Enable **Resolve Names** (checkbox at the bottom) to attempt DNS resolution of external IPs
- Look for:
  - Internal IPs communicating with unexpected external IPs
  - Single IPs with extremely high byte totals
  - IPs you don't recognise on internal subnets

<!-- IMAGE-04: Wireshark → Statistics → Endpoints → IPv4 tab sorted by Bytes (descending) -->
<p align="center">
  <img src="./Evidences/4.png" width="75%" alt="Endpoints - IPv4 sorted by Bytes (Descending)" />
</p>
<p align="center"><em>Figure 4: Wireshark Endpoints – IPv4 tab sorted by Bytes (descending)</em></p>

<!-- IMAGE-05: Wireshark → Statistics → Endpoints → IPv4 tab sorted by Tx Bytes (outbound) -->
<p align="center">
  <img src="./Evidences/5.png" width="75%" alt="Endpoints - IPv4 sorted by Tx Bytes (Outbound)" />
</p>
<p align="center"><em>Figure 5: Wireshark Endpoints – IPv4 tab sorted by Tx Bytes (outbound)</em></p>

**Key Observations — Endpoints IPv4 (sorted by Bytes):**

- `10.5.26.4` is the **primary victim machine** with the highest total traffic of **12 MB**
  across 17,004 packets — this host was the **main target** of the Trickbot infection
- `192.236.155.230` is the **top external IP** with **7 MB** transferred —
  significantly higher than other external IPs = **primary C2 server or exfiltration destination**
- `37.228.70.134` and `45.229.71.211` both show **169 kB** each —
  appearing consistently in endpoints confirms these are **active C2 beaconing servers**
---
**Key Observations — Endpoints IPv4 (sorted by Tx Bytes):**

- `192.236.155.230` ranks **#1 in Tx Bytes with 7 MB** outbound —
  an external IP sending this much data to internal hosts strongly indicates
  **payload delivery or malware staging**
- `78.186.110.14`, `91.83.88.122` each sent **2 MB** outbound —
  multiple external IPs actively pushing data = **coordinated C2 infrastructure**
- `10.5.26.136` and `10.5.26.134` both show **97 kB Tx Bytes** —
  these internal IPs are also communicating outbound = **lateral movement within the network**
---

## Section 3 · Conversations

### What are Conversations?

A **conversation** is a two-way communication exchange between two specific endpoints. While endpoints tell you *who* is on the network, conversations tell you *who is talking to whom*.

```
IP A  ↔  IP B  =  one conversation
10.5.26.132  ↔  192.236.155.230  =  one conversation
```

In forensics, conversations are critical because they reveal:
- Which internal host is communicating with a suspicious external IP
- How long that communication lasted (long-duration sessions = potential C2 beaconing)
- How much data was transferred in each session (high bytes = potential exfiltration)
- Whether a single internal host has many connections to different external IPs (scanning behaviour)

### Steps — Conversations

- Go to **Statistics → Conversations**
- Select the tab for the layer you want to analyse:

| Tab | What it shows |
|-----|---------------|
| **Ethernet** | MAC address pairs |
| **IPv4** | IP address pairs ✅ Most useful for forensics |
| **IPv6** | IPv6 address pairs |
| **TCP** | IP:Port pairs — shows exact sessions |
| **UDP** | UDP sessions |

- Click column headers to sort:
  - **Bytes** — heaviest data transfer (potential exfiltration)
  - **Packets** — most active conversations
  - **Duration** — longest-running sessions ✅ Key for C2 detection (C2 beacons keep sessions alive)
- Right-click any conversation → **Apply as Filter** to isolate that traffic in the main packet list

<!-- IMAGE-06: Wireshark → Statistics → Conversations → IPv4 tab sorted by Bytes (descending) -->
<p align="center">
  <img src="./Evidences/6.png" width="75%" alt="Conversations - IPv4 sorted by Bytes" />
</p>
<p align="center"><em>Figure 6: Wireshark Conversations – IPv4 tab sorted by Bytes (descending)</em></p>

<!-- IMAGE-07: Wireshark → Statistics → Conversations → TCP tab sorted by Duration (long-lived sessions) -->
<p align="center">
  <img src="./Evidences/7.png" width="75%" alt="Conversations - TCP Sorted by Duration (Long-lived Sessions)" />
</p>
<p align="center"><em>Figure 7: Wireshark Conversations – TCP tab sorted by Duration (long-lived sessions)</em></p>

**Key Observations — IPv4 Conversations (sorted by Bytes):**

- `10.5.26.4 ↔ 192.236.155.230` is the **heaviest conversation** with **4 MB** transferred
  across 3,810 packets — strongly indicates **C2 communication or data exfiltration**
- `10.5.26.4 ↔ 78.186.110.14` and `10.5.26.4 ↔ 91.83.88.122` each transferred **2 MB**
  — multiple external IPs communicating with the same victim machine suggests
  **multi-stage Trickbot payload delivery**
- `10.5.26.4 ↔ 5.199.162.3` transferred **1 MB** with a duration of **1025 seconds**
  — longest running conversation = **persistent C2 beacon session**

---
**Key Observations — TCP Conversations (sorted by Duration):**

- `10.5.26.4 → 5.199.162.3` on **Port 80** lasted **101 seconds** with only 208 kB transferred
  — low data over long duration = classic **Cobalt Strike beacon keep-alive behavior**
- `10.5.26.4` and `10.5.26.132` have **multiple long-lived TCP sessions** with
  `45.229.71.211` and `37.228.70.134` all lasting **67–89 seconds** = **persistent
  C2 connections maintained over time**
- All suspicious external IPs communicate over **Port 443 and Port 80**
  — attackers using standard web ports to **blend in with normal traffic and evade detection**
---

## Section 4 · Top Talkers

### What are Top Talkers?

Top talkers are the IP addresses that **generate the most traffic** in the capture — measured by total bytes sent and received. Identifying top talkers quickly focuses your investigation on the most active hosts.

In a malware scenario:
- **An infected host** often becomes a top talker due to C2 check-ins, payload downloads, or lateral movement traffic
- **An exfiltrating host** sends unusually high outbound bytes to an external IP
- **A scanning host** generates high packet counts but relatively low byte counts

### Steps — Top Talkers

- Go to **Statistics → Endpoints → IPv4 tab**
- Click the **Bytes** column header to sort descending — the top entries are your heaviest talkers
- Click **Tx Bytes** to find hosts sending the most data outbound (relevant for exfiltration)
- Click **Rx Bytes** to find hosts receiving the most data (relevant for payload downloads)
- Enable **Resolve Names** at the bottom to map IPs to hostnames where possible
- Cross-reference the top talkers against your known internal IP range — any unfamiliar IPs deserve investigation

<!-- IMAGE-08: Wireshark → Statistics → Endpoints → IPv4 tab sorted by Bytes – Top 15 Talkers -->
<p align="center">
  <img src="./Evidences/8.png" width="75%" alt="Endpoints - IPv4 Top 15 Talkers sorted by Bytes" />
</p>
<p align="center"><em>Figure 8: Wireshark Endpoints – IPv4 tab Top 15 Talkers sorted by Bytes (descending)</em></p>

<!-- IMAGE-09: Wireshark → Statistics → Endpoints → IPv4 tab sorted by Tx Bytes (outbound) – Top 15 Talkers -->
<p align="center">
  <img src="./Evidences/9.png" width="75%" alt="Endpoints - IPv4 Top 15 Talkers sorted by Tx Bytes" />
</p>
<p align="center"><em>Figure 9: Wireshark Endpoints – IPv4 tab Top 15 Talkers sorted by Tx Bytes (outbound)</em></p>

**Key Observations:**

- `192.236.155.230` is the **#1 suspicious external IP** — sending 7MB outbound = possible **data exfiltration**
- `10.5.26.4` and `10.5.26.132` are the **primary victim machines**
- External IPs `37.228.70.134` and `45.229.71.211` appear in **both lists** = confirmed **C2 servers**
- High Tx Bytes from external IPs = **payload delivery to victims**
---

## Section 5 · Time Bounds

### What are Time Bounds?

Time bounds define the **start time and end time** of the captured network traffic. Every packet in a PCAP has a precise timestamp. Identifying the time bounds lets you:

- Understand when an incident started and ended
- Calculate the total duration of the capture window
- Correlate network events with system logs, IDS alerts, and endpoint telemetry
- Build a timeline that maps the attack progression

### Steps — Time Bounds

**Method 1 — Capture File Properties (Easiest)**
- Open your `.pcap` in Wireshark
- Go to **Statistics → Capture File Properties**
- The dialog shows:
  - **First Packet** — timestamp of the very first captured packet (Start Time)
  - **Last Packet** — timestamp of the last captured packet (End Time)
  - **Elapsed Time** — total duration of the capture session
<!-- IMAGE-10: Wireshark → Statistics → Capture File Properties showing 
First Packet (Start Time), Last Packet (End Time), and Elapsed Time (Duration) -->
<p align="center"> 
  <img src="./Evidences/10.png" width="75%" alt="PCAP File Properties - File Name, Packet Count, Start Time, End Time and Duration" />
</p>
<p align="center"><em>Figure 10: Wireshark Statistics – Capture File Properties showing Start Time, End Time and Total Duration</em></p>

**Method 2 — Packet List View**
- Look at the first row in the packet list — that is your Start Time
- Press `Ctrl + End` to jump to the last packet — that is your End Time
- The **Time** column shows relative or absolute timestamps per packet

**Method 3 — I/O Graph (Visual)**
- Go to **Statistics → I/O Graph**
- The X-axis spans the full time range of the capture
- Useful for seeing the overall window at a glance

<!-- IMAGE-11: Wireshark → Statistics → I/O Graph showing full X-axis time range of the capture -->
<p align="center">
  <img src="./Evidences/11.png" width="75%" alt="Time Bounds - I/O Graph showing Full X-axis Time Range of the Capture" />
</p>
<p align="center"><em>Figure 11: Wireshark Statistics – I/O Graph showing full X-axis Time Range of the Capture</em></p>

---

## Section 6 · Anomalous Bursts

### What are Anomalous Bursts?

Anomalous bursts are **sudden, sharp spikes in traffic volume** that deviate significantly from the established baseline. A burst is only meaningful *after* you have characterised the normal — hence why time bounds and protocol distribution come first.

Bursts can indicate:
- **Data exfiltration** — large outbound spike to an external IP
- **Lateral movement** — sudden east-west traffic spike across internal segments
- **Malware payload download** — a one-time burst of inbound HTTP bytes
- **C2 beaconing** — periodic small spikes at regular intervals
- **Scanning activity** — high packet count with low byte count per burst

> **Key finding in this PCAP:** The interval between 300–900 seconds shows ~15,000 frames and ~15 MB transferred in just 10 minutes — approximately 10× the baseline of 230 kB per interval. This correlates with the Trickbot payload download and initial Cobalt Strike C2 beaconing.

### Steps — I/O Graph

- Go to **Statistics → I/O Graph**
- Set the **X-axis interval** to `1 sec`, `10 sec`, or `60 sec` depending on the granularity needed
- Look for **sharp vertical spikes** — those are the bursts
- Click on a spike bar to jump directly to the corresponding packets in the packet list
- Use **display filters** at the bottom of the I/O Graph to isolate bursts by protocol:
  - `tcp` — TCP-only bursts
  - `http` — HTTP payload bursts
  - `ip.addr == 192.236.155.230` — bursts involving a specific suspicious IP
- Add multiple filter lines to overlay different protocols and compare their burst patterns

<!-- IMAGE-12: Wireshark → Statistics → I/O Graph — zoomed in on burst window (300–900s) with HTTP filter applied -->
<p align="center">
  <img src="./Evidences/12.png" width="75%" alt="Anomalous Bursts - I/O Graph Zoomed in on Burst Window (300-900s) with HTTP Filter Applied" />
</p>
<p align="center"><em>Figure 12: Wireshark Statistics – I/O Graph zoomed in on Burst Window (300–900s) with HTTP Filter Applied</em></p>
**Graph Analysis — I/O Graph (tcp.port == 80)**

| Detail | Value |
|---|---|
| **Filter** | `tcp.port == 80` |
| **Interval** | 10 sec |
| **Burst Spike 1** | Around 400–450 seconds → ~1.25 kpkts |
| **Burst Spike 2** | Around 800–850 seconds → ~1.25 kpkts |
| **Pattern** | Two sharp identical bursts = periodic C2 communication |

> ⚠️ **Suspicious Activity Detected:**
> - Two **identical spikes** appearing at regular intervals
> - Suggests **Trickbot/Cobalt Strike beacon** firing at scheduled intervals over HTTP (port 80)
> - Flat traffic between spikes indicates the malware was **sleeping/waiting** between C2 check-ins

*Triage Pass · Wireshark GUI Guide · Project KAVACH · Futurense AI Clinic × IIT Roorkee · Confidential*
