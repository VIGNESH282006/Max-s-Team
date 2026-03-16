#!/usr/bin/env python3
"""Quick OSINT functionality test."""

from osint import analyze_ioc, get_threat_intelligence, ThreatIntelligence

# Test 1: Create OSINT instance
print("=" * 60)
print("OSINT THREAT INTELLIGENCE SYSTEM - FUNCTIONAL TEST")
print("=" * 60)

ti = get_threat_intelligence()
print("\n✓ OSINT database initialized")

# Test 2: IP lookup - clean IP
result = ti.lookup_ip("8.8.8.8")
assert result["ip"] == "8.8.8.8"
assert result["is_malicious"] == False
assert result["severity"] == "clean"
print("✓ Clean IP lookup: 8.8.8.8 -> CLEAN")

# Test 3: IP lookup - known bad IP
result = ti.lookup_ip("203.0.113.50")
assert result["is_malicious"] == True
assert "darkweb_exit_node" in result["categories"]
print("✓ Darkweb IP lookup: 203.0.113.50 -> MALICIOUS (darkweb_exit_node)")

# Test 4: C2 server lookup
result = ti.lookup_ip("102.165.212.60")
assert result["is_malicious"] == True
assert "c2_infrastructure" in result["categories"]
print("✓ C2 server lookup: 102.165.212.60 -> CRITICAL (c2_infrastructure)")

# Test 5: Port lookup - suspicious port
result = ti.lookup_port(445, "tcp")
assert result["is_suspicious"] == True
assert "lateral_movement_target" in result["categories"]
print("✓ Suspicious port: 445/tcp -> LATERAL_MOVEMENT_TARGET")

# Test 6: Domain lookup - malware domain
result = ti.lookup_domain("malware-c2.xyz")
assert result["is_malicious"] == True
assert "c2_infrastructure" in result["categories"]
print("✓ C2 domain lookup: malware-c2.xyz -> CRITICAL")

# Test 7: Full log analysis with threats
test_log = {
    "source_ip": "203.0.113.50",
    "dest_ip": "10.0.1.100",
    "dest_port": 445,
    "protocol": "tcp",
    "action": "connection",
    "user_id": "user_001",
}

ioc_result = analyze_ioc(test_log)
print(f"\n✓ Full log analysis:")
print(f"  - IOC Status: {'YES' if ioc_result['is_ioс'] else 'NO'}")
print(f"  - Severity: {ioc_result['severity'].upper()}")
print(f"  - Threats Found: {len(ioc_result['threats_found'])}")
print(f"  - Summary: {ioc_result['summary']}")

if ioc_result['threats_found']:
    for threat in ioc_result['threats_found']:
        print(f"    • {threat['type'].upper()}: {threat['indicator']} ({threat['severity']})")
        print(f"      Categories: {', '.join(threat['categories'])}")

# Test 8: Clean log analysis
clean_log = {
    "source_ip": "8.8.8.8",
    "dest_ip": "10.0.1.100",
    "dest_port": 443,
    "protocol": "https",
    "action": "connection",
    "user_id": "user_001",
}

clean_result = analyze_ioc(clean_log)
print(f"\n✓ Clean log analysis:")
print(f"  - IOC Status: {'YES' if clean_result['is_ioс'] else 'NO'}")
print(f"  - Severity: {clean_result['severity'].upper()}")
print(f"  - Summary: {clean_result['summary']}")

print("\n" + "=" * 60)
print("ALL TESTS PASSED - OSINT SYSTEM FUNCTIONAL")
print("=" * 60)
