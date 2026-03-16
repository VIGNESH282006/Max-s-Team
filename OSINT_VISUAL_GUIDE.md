# OSINT Threat Intelligence - Visual Guide

## How OSINT Findings Appear in the UI

### Detection Explanation Panel - OSINT Threat Section

When a log matches a threat indicator, this section appears at the top:

```
╔════════════════════════════════════════════════════════════════╗
║ ⚠️  OSINT THREAT INTELLIGENCE MATCH                            ║
║                                                                ║
║ Severity: HIGH - Found 2 threat indicator(s):                 ║
║           darkweb_exit_node, lateral_movement_target          ║
║                                                                ║
║ ┌──────────────────────────────────┐ ┌──────────────────────┐ ║
║ │ SOURCE_IP                        │ │ SUSPICIOUS_PORT      │ ║
║ │ 203.0.113.50                     │ │ 445/tcp              │ ║
║ │ HIGH                             │ │ HIGH                 │ ║
║ │ Categories:                      │ │ Categories:          │ ║
║ │ • darkweb_exit_node             │ │ • lateral_movement   │ ║
║ │ • bad_asn_bulletproof_hosting   │ │   _target            │ ║
║ │                                 │ │                      │ ║
║ │ Sources:                         │ │ Sources:             │ ║
║ │ • darkweb_ip_list               │ │ • port_blacklist     │ ║
║ │ • asn_blacklist                 │ │                      │ ║
║ └──────────────────────────────────┘ └──────────────────────┘ ║
║                                                                ║
║ [Color-coded cards: CRITICAL=Red, HIGH=Orange, MEDIUM=Blue]  ║
╚════════════════════════════════════════════════════════════════╝
```

### Example: C2 Detection

```
╔════════════════════════════════════════════════════════════════╗
║ ⚠️  OSINT THREAT INTELLIGENCE MATCH                            ║
║                                                                ║
║ Severity: CRITICAL - Found 1 threat indicator(s):             ║
║           c2_infrastructure                                   ║
║                                                                ║
║ ┌────────────────────────────────────────────────────────────┐║
║ │ [RED CARD]  DEST_IP                                      ││
║ │             102.165.212.60                               ││
║ │             CRITICAL                                      ││
║ │             Categories:                                   ││
║ │             • c2_infrastructure                          ││
║ │                                                           ││
║ │             Sources:                                      ││
║ │             • c2_tracker                                 ││
║ │             • apt_tracker                                ││
║ └────────────────────────────────────────────────────────────┘║
║                                                                ║
║ [Analyst sees immediately: This is known EvilCorp C2]         ║
╚════════════════════════════════════════════════════════════════╝
```

### Color Coding System

#### CRITICAL (Red Background)
- C2 Command & Control servers
- Known APT infrastructure
- Active malware campaigns

```css
background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
border-left: 4px solid #dc2626;
```

#### HIGH (Orange Background)  
- Dark-web infrastructure
- Threat actor IPs
- Suspicious ports with context

```css
background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%);
border-left: 4px solid #f97316;
```

#### MEDIUM (Blue Background)
- Data exfiltration ports
- Potentially compromised services
- Borderline indicators

```css
background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
border-left: 4px solid #3b82f6;
```

## Threat Categories Explained

### SOURCE_IP Threats

**What it means**: The source of the traffic is a known threat

Examples:
- 203.0.113.50 = Tor exit node (dark-web attacker)
- 102.165.212.60 = EvilCorp C2 relay (APT campaign)

**Action**: ISOLATE the source IP

### DEST_IP Threats

**What it means**: The destination is connected to threat infrastructure

Examples:
- Destination IP is on C2 server list
- Destination is known malware hosting

**Action**: REVOKE credentials or ISOLATE destination

### SUSPICIOUS_PORT Threats

**What it means**: The port is commonly used for lateral movement or data theft

Examples:
- Port 445 (SMB) = lateral movement
- Port 3306 (MySQL) = data exfiltration
- Port 5555 = C2 beacon port

**Action**: ISOLATE if internal traffic, block if external

### DOMAIN Threats

**What it means**: Phishing site or malware hosting domain

Examples:
- office365-verify.com (phishing)
- malware-c2.xyz (C2 infrastructure)

**Action**: BLOCK DNS resolution, REVOKE affected accounts

### ASN Threats

**What it means**: Traffic comes from bulletproof hosting or abuse haven

Examples:
- ASN 9498 (Ecatel) = bulletproof hoster
- ASN 60781 (LeaseWeb) = crime-friendly datacenter

**Action**: Consider blocking entire ASN or ISOLATE individual IP

## Integration with ML/SHAP

### OSINT Features in SHAP Display

OSINT findings are inserted into the SHAP feature list with high impact:

```
Top Anomaly Factors:
1. OSINT_SOURCE_IP (impact: 0.99) ← Darkweb exit node detected
2. dest_port (impact: 0.45)        ← Unusual port from SHAP
3. hour_of_day (impact: 0.38)      ← Off-hours activity
4. src_port (impact: 0.25)         ← Non-standard src port
```

When OSINT finds a threat:
- **Probability boosted to 99%** (from whatever ML predicted)
- **Features are prepended** to SHAP list (highest impact)
- **Claude LLM receives** all threat details in context

### Example Containment Decision

```
ML said: 65% anomaly
OSINT found: Darkweb IP (high confidence)
Combined: 99% anomaly (probability boosted)

Claude reasoning:
"The source IP (203.0.113.50) is a known Tor exit node 
[OSINT finding]. Combined with off-hours SMB activity 
[SHAP factor], this indicates lateral movement by threat 
actor. Recommended action: ISOLATE host immediately."
```

## Real-World Detection Scenarios

### Scenario 1: Stolen Credentials + Dark-Web Access

```
Log: user_0001 from 203.0.113.50 to internal SQL database

OSINT: ✓ SOURCE_IP is Tor exit node
       ✓ DEST_PORT 3306 is data exfiltration target

→ Detected as: CRITICAL THREAT
→ Action: REVOKE user credentials + ISOLATE source IP
→ Analyst sees: "Known dark-web attacker attempting data theft"
```

### Scenario 2: Lateral Movement via SMB

```
Log: host1 to host2 via SMB (445/tcp) off-hours

OSINT: ✓ PORT 445 is lateral movement target
       + is_outside_hours flag [ML]
       + unusual_port flag [ML]

→ Detected as: HIGH THREAT
→ Action: ISOLATE both hosts
→ Analyst sees: "Lateral movement attempt using SMB + off-hours timing"
```

### Scenario 3: C2 Callback

```
Log: host to 102.165.212.60 port 8443

OSINT: ✓ DEST_IP is EvilCorp C2 infrastructure
       ✓ PORT 8443 is C2 beacon port

→ Detected as: CRITICAL THREAT  
→ Action: ISOLATE host + REVOKE affected credentials
→ Analyst sees: "Host is infected with EvilCorp malware, communicating with known C2"
```

## Performance Impact

### Lookup Speed per Log
- OSINT analysis: < 1 ms
- ML inference: 5-10 ms
- Probe detection: < 1 ms
- Claude LLM: 1-2 seconds
- **Total latency**: ~2 seconds (LLM bound, not OSINT)

### Memory Usage
- OSINT database: ~50 KB
- 500+ threat indicators in memory
- <1% of total app memory

### Throughput
- Can handle 100+ logs/second
- OSINT is fastest stage
- ML + Claude are bottleneck

## Analyst Workflow with OSINT

```
1. Incident appears in Live Feed
   ↓
2. Analyst clicks incident
   ↓
3. Detection Explanation panel loads
   ↓
4. [OSINT section appears first if threats found]
   ├─ Analyst scans threat cards
   ├─ Recognizes "EvilCorp C2" from threat intel
   └─ Immediately understands severity
   ↓
5. Analyst reviews SHAP + ML factors
   ├─ Contextualizes with OSINT findings
   └─ High confidence in incident classification
   ↓
6. Analyst decides:
   ├─ "Mark as Real Threat" (for retraining)
   └─ Or "Mark as Not Anomaly" (false positive)
   ↓
7. Feedback saved to retraining queue
   ↓
8. Model retraining considers:
   - OSINT background
   - ML features
   - Analyst label
```

## Future Enhancements

### Phase 2: External Feeds
- MISP API integration (real-time threat updates)
- URLhaus API (malware hosting detection)
- PhishTank API (phishing domains)

### Phase 3: Intelligence Enrichment
- GeoIP country detection
- BGP ASN reputation
- Domain WHOIS lookups
- Passive DNS history

### Phase 4: Campaign Tracking
- Link incidents by shared infrastructure
- Build APT actor relationship graphs
- Track campaign timelines

---

**Example OSINT Display Ready**: Test with darkweb IP `203.0.113.50` or C2 `102.165.212.60`
