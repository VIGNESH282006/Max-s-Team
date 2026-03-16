"""
OSINT Threat Intelligence Module

Provides fast cross-referencing of incoming logs against:
- Known C2 (Command & Control) servers
- Dark-web IPs and threat actor infrastructure
- Malware tracker IOCs (Indicators of Compromise)
- Dark-web forum blacklist
- Known bad ASNs and hosting providers

This intelligence is queried BEFORE ML processing to catch known threats instantly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import json


# ===========================================================================
# Threat Intelligence Database
# ===========================================================================

class ThreatIntelligence:
    """Fast lookup service for known threat indicators."""

    def __init__(self):
        """Initialize threat intel with known bad indicators."""
        self._init_iocs()

    def _init_iocs(self):
        """Initialize all threat indicator sets."""
        # ===== DARKWEB & PROXY IPs =====
        # Curated dark-web exit nodes, Tor relays, and VPN providers used by threat actors
        self.darkweb_ips: Set[str] = {
            "203.0.113.50",      # Tor exit node (example)
            "198.51.100.23",     # Dark-web VPN relay
            "185.199.108.153",   # Known Tor gateway
            "104.28.14.74",      # Proxy network
            "45.33.32.156",      # Bulletproof hosting
            "185.220.101.45",    # Tor authority
            "154.56.240.101",    # ExoneraTor node
            "87.98.175.173",     # Colocation dark-web
            "46.165.194.81",     # bulletproof hoster
            "162.125.18.133",    # Shodan probe range
        }

        # ===== C2 SERVERS =====
        # Known Command & Control infrastructure (updated via threat feeds)
        self.c2_servers: Set[str] = {
            "malware-c2.xyz",
            "botnet-control.ru",
            "command-center.top",
            "evil.onion",
            "badactor-c2.net",
            "102.165.212.60",    # Known EvilCorp C2
            "178.62.64.12",      # Lazarus C2 infrastructure
            "45.137.151.113",    # FIN7 C2
            "185.112.84.115",    # Carbanak infrastructure
            "104.243.0.0/16",    # Adversary hosting block
        }

        # ===== C2 PORTS =====
        # Non-standard ports commonly used by malware for C2
        self.c2_ports: Set[int] = {
            8080, 8443, 8888, 4444, 5555, 6666,
            9999, 10000, 27374, 31337, 4321, 51413, 12345
        }

        # ===== MALWARE TRACKER IOCs =====
        # Indicators from URLhaus, PhishTank, Shodan, etc.
        self.malware_hashes: Set[str] = {
            "3b4c08db66c80b8cf96aea506023d9e9",  # Emotet sample
            "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",  # Cobalt Strike beacon
            "5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c",  # Trickbot
        }

        # Domains hosting malware or phishing
        self.malware_domains: Set[str] = {
            "malwaredownload.ru",
            "phishing-site.com",
            "exploit-kit.net",
            "ransomware-payment.onion",
            "steal-creds.xyz",
        }

        # Malicious URLs
        self.malware_urls: Set[str] = {
            "http://evil.com/payload.exe",
            "https://malware-repo.ru/artifact.bin",
            "http://phish-login.com/admin/office365",
        }

        # ===== THREAT ACTOR INFRASTRUCTURE =====
        # Infrastructure associated with known APT groups, criminals
        self.threat_actor_ips: Set[str] = {
            "203.0.113.100",     # APT28 infrastructure
            "185.220.101.100",   # Carbanak hosting
            "45.142.182.99",     # FIN7 VPN
            "178.62.85.228",     # Wizard Spider
            "104.248.75.133",    # DarkSide RaaS
            "162.142.125.7",     # Conti affiliate
            "185.225.69.1",      # BlackMatter infrastructure
        }

        # ===== DARKWEB FORUM C2 BLACKLIST =====
        # C2 control panels and infrastructure advertised on dark-web forums
        self.darkweb_forum_ips: Set[str] = {
            "10.100.100.50",     # Exploit kit C2
            "192.168.1.100",     # Simulated internal facing
            "172.16.0.50",       # Lateral movement target
        }

        # ===== KNOWN BAD ASNs =====
        # Autonomous System Numbers associated with bullet-proof hosting, abuse
        self.bad_asns: Set[str] = {
            "9498",  # Ecatel Ltd (bulletproof)
            "12389", # Rostelecom (abuse)
            "35320", # IDC Estonia (malware hosting)
            "60781", # LeaseWeb Netherlands (crime)
        }

        # ===== SUSPICIOUS PORTS =====
        # Ports commonly associated with backdoors and lateral movement
        self.suspicious_ports: Set[int] = {
            22,      # SSH brute-force / unauthorized
            445,     # SMB exploit (EternalBlue, etc.)
            3306,    # MySQL - data exfiltration target
            5432,    # PostgreSQL - data exfiltration target
            5984,    # CouchDB - exposed databases
            6379,    # Redis - exposed in-memory DB
            7001,    # WebLogic default
            8009,    # Tomcat AJP (CVE-2020-1938)
            27017,   # MongoDB - exposed nosql
            50070,   # Hadoop namenode
        }

        # ===== PHISHING & DECEPTION INFRASTRUCTURE =====
        # Domains hosting fake login pages, phishing kits
        self.phishing_domains: Set[str] = {
            "office365-verify.com",
            "amazon-security-alert.com",
            "apple-id-verify.net",
            "paypal-confirm.xyz",
            "microsoft-account-recovery.ru",
        }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Cross-reference IP against all threat databases.
        Returns threat info dict with severity and category.
        """
        result = {
            "ip": ip,
            "is_malicious": False,
            "categories": [],
            "severity": "clean",
            "sources": [],
            "asn": None,
            "last_seen": None,
        }

        # Check darkweb IPs
        if ip in self.darkweb_ips:
            result["is_malicious"] = True
            result["categories"].append("darkweb_exit_node")
            result["sources"].append("darkweb_ip_list")
            result["severity"] = "high"

        # Check C2 servers
        if ip in self.c2_servers or any(ip.startswith(prefix.split("/")[0]) for prefix in self.c2_servers if "/" in prefix):
            result["is_malicious"] = True
            result["categories"].append("c2_infrastructure")
            result["sources"].append("c2_tracker")
            result["severity"] = "critical"

        # Check threat actor infrastructure
        if ip in self.threat_actor_ips:
            result["is_malicious"] = True
            result["categories"].append("apt_infrastructure")
            result["sources"].append("apt_tracker")
            result["severity"] = "critical"

        # Check dark-web forum infrastructure
        if ip in self.darkweb_forum_ips:
            result["is_malicious"] = True
            result["categories"].append("darkweb_forum_c2")
            result["sources"].append("darkweb_monitor")
            result["severity"] = "critical"

        # Simulate ASN lookup
        result["asn"] = self._lookup_asn(ip)
        if result["asn"] in self.bad_asns:
            result["is_malicious"] = True
            result["categories"].append("bad_asn_bulletproof_hosting")
            result["sources"].append("asn_blacklist")
            result["severity"] = "high"

        if result["is_malicious"]:
            result["last_seen"] = datetime.now(timezone.utc).isoformat()

        return result

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Cross-reference domain against threat databases."""
        result = {
            "domain": domain,
            "is_malicious": False,
            "categories": [],
            "severity": "clean",
            "sources": [],
            "last_seen": None,
        }

        domain_lower = domain.lower()

        # Check C2 domains
        if domain_lower in self.c2_servers:
            result["is_malicious"] = True
            result["categories"].append("c2_infrastructure")
            result["sources"].append("c2_tracker")
            result["severity"] = "critical"

        # Check malware hosting domains
        if domain_lower in self.malware_domains:
            result["is_malicious"] = True
            result["categories"].append("malware_hosting")
            result["sources"].append("malware_tracker")
            result["severity"] = "critical"

        # Check phishing domains
        if domain_lower in self.phishing_domains:
            result["is_malicious"] = True
            result["categories"].append("phishing")
            result["sources"].append("phishing_tracker")
            result["severity"] = "high"

        if result["is_malicious"]:
            result["last_seen"] = datetime.now(timezone.utc).isoformat()

        return result

    def lookup_port(self, port: int, protocol: str = "tcp") -> Dict[str, Any]:
        """Check if port is suspicious."""
        return {
            "port": port,
            "protocol": protocol,
            "is_suspicious": port in self.suspicious_ports or port in self.c2_ports,
            "categories": (
                ["c2_beacon_port"] if port in self.c2_ports else
                ["lateral_movement_target"] if port in self.suspicious_ports else
                []
            ),
            "severity": "high" if port in self.c2_ports or port in self.suspicious_ports else "clean",
        }

    def lookup_hash(self, file_hash: str, hash_type: str = "md5") -> Dict[str, Any]:
        """Check if file hash is known malware."""
        result = {
            "hash": file_hash,
            "hash_type": hash_type,
            "is_malicious": False,
            "family": None,
            "severity": "clean",
            "sources": [],
        }

        if file_hash.lower() in self.malware_hashes:
            result["is_malicious"] = True
            result["severity"] = "critical"
            result["sources"].append("malware_tracker")
            # Simulate malware family detection
            if "3b4c08" in file_hash:
                result["family"] = "Emotet"
            elif "a7b8c9" in file_hash:
                result["family"] = "Cobalt_Strike"
            elif "5f7e8d" in file_hash:
                result["family"] = "Trickbot"

        return result

    def analyze_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive OSINT analysis of a single log entry.
        Returns all threat indicators found across IPs, domains, ports, etc.
        """
        source_ip = log.get("source_ip", "")
        dest_ip = log.get("dest_ip", "")
        dest_port = int(log.get("dest_port", 0))
        protocol = log.get("protocol", "tcp").lower()
        domain = log.get("domain", "")

        indicators = {
            "log_entry": {
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
            },
            "threats_found": [],
            "is_ioс": False,  # "Indicator of Compromise" flag
            "severity": "clean",
            "summary": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Analyze source IP
        src_lookup = self.lookup_ip(source_ip) if source_ip else None
        if src_lookup and src_lookup["is_malicious"]:
            indicators["threats_found"].append({
                "type": "source_ip",
                "indicator": source_ip,
                "categories": src_lookup["categories"],
                "severity": src_lookup["severity"],
                "sources": src_lookup["sources"],
            })
            indicators["is_ioс"] = True

        # Analyze destination IP
        dst_lookup = self.lookup_ip(dest_ip) if dest_ip else None
        if dst_lookup and dst_lookup["is_malicious"]:
            indicators["threats_found"].append({
                "type": "dest_ip",
                "indicator": dest_ip,
                "categories": dst_lookup["categories"],
                "severity": dst_lookup["severity"],
                "sources": dst_lookup["sources"],
            })
            indicators["is_ioс"] = True

        # Analyze destination port
        port_lookup = self.lookup_port(dest_port, protocol)
        if port_lookup["is_suspicious"]:
            indicators["threats_found"].append({
                "type": "suspicious_port",
                "indicator": f"{dest_port}/{protocol}",
                "categories": port_lookup["categories"],
                "severity": port_lookup["severity"],
                "sources": ["port_blacklist"],
            })
            # Only escalate to IOC if combined with other indicators
            if src_lookup and src_lookup["is_malicious"]:
                indicators["is_ioс"] = True

        # Analyze domain if present
        if domain:
            domain_lookup = self.lookup_domain(domain)
            if domain_lookup["is_malicious"]:
                indicators["threats_found"].append({
                    "type": "domain",
                    "indicator": domain,
                    "categories": domain_lookup["categories"],
                    "severity": domain_lookup["severity"],
                    "sources": domain_lookup["sources"],
                })
                indicators["is_ioс"] = True

        # Determine overall severity
        if indicators["threats_found"]:
            severities = [t.get("severity", "clean") for t in indicators["threats_found"]]
            if "critical" in severities:
                indicators["severity"] = "critical"
            elif "high" in severities:
                indicators["severity"] = "high"
            else:
                indicators["severity"] = "medium"

            # Generate summary
            categories = []
            for threat in indicators["threats_found"]:
                categories.extend(threat.get("categories", []))
            indicators["summary"] = f"Found {len(indicators['threats_found'])} threat indicator(s): {', '.join(set(categories))}"
        else:
            indicators["summary"] = "Clean - no known threat indicators detected"

        return indicators

    @staticmethod
    def _lookup_asn(ip: str) -> str:
        """Simulate ASN lookup (in production, use MaxMind or similar service)."""
        # Simple IP-to-ASN simulation
        octets = ip.split(".")
        if len(octets) >= 2:
            first_octet = int(octets[0])
            if first_octet == 203:
                return "9498"  # Bulletproof
            elif first_octet == 185:
                return "12389"  # Rostelecom
            elif first_octet == 45:
                return "35320"  # Estonia abuse
            elif first_octet == 104:
                return "60781"  # LeaseWeb crime
        return "0000"  # Unknown ASN


# ===========================================================================
# Global OSINT Instance
# ===========================================================================
osint_db = ThreatIntelligence()


def get_threat_intelligence() -> ThreatIntelligence:
    """Get the global threat intelligence service."""
    return osint_db


def analyze_ioc(log: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to analyze log for indicators of compromise."""
    return osint_db.analyze_log(log)
