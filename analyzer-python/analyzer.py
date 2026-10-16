import hashlib
import ipaddress
import math
import re
from collections import Counter
from typing import Dict, List, Any

import requests


class CTIAnalyzer:
    """
    Kurumsal Siber Tehdit İstihbaratı (CTI) Metin Analiz, IOC Çıkarımı,
    GeoIP/ASN Zenginleştirme, Shannon Entropi ve Dinamik Risk Skorlama Motoru.
    """

    RE_CREDENTIAL = re.compile(
        r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s:]{5,64})\b'
    )
    RE_EMAIL = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    )
    RE_IPV4 = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
    )
    RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    RE_IBAN = re.compile(r'\bTR\d{2}\s?(?:\d{4}\s?){5}\d{2}\b')
    RE_DOMAIN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com\.tr|org\.tr|gov\.tr|edu\.tr|net\.tr|com|net|org|io|onion|gov|edu|de|uk|ru|cn|br|au)\b',
        re.IGNORECASE,
    )
    RE_COUNTRY = re.compile(r'(?:Country:\s*([A-Z]{2})|\(([A-Z]{2})\)\s*$)')
    RE_GROUP = re.compile(r'(?:\[RANSOMWARE:\s*([^\]]+)\]|Group:\s*([A-Za-z0-9_ -]+))')

    API_KEY_PATTERNS = {
        "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        "GitHub Token": re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b'),
        "Stripe Live Key": re.compile(r'\bsk_live_[0-9a-zA-Z]{24,99}\b'),
        "Slack Token": re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b'),
        "Private Key Header": re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    }

    RE_TOKEN_CANDIDATE = re.compile(r'\b[A-Za-z0-9+/=_/-]{28,128}\b')

    def __init__(self):
        self._geoip_cache: Dict[str, Dict[str, str]] = {}

    @staticmethod
    def compute_sha256(text: str) -> str:
        normalized = "\n".join(
            line.strip() for line in text.strip().splitlines() if line.strip()
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            )
        except ValueError:
            return False

    def enrich_ips(self, ips: List[str]) -> List[Dict[str, str]]:
        """Genel (Public) IPv4 adreslerini GeoIP, Ülke Kodu ve ASN/ISP bilgisiyle zenginleştirir."""
        enriched = []
        public_ips = [ip for ip in ips if self.is_public_ip(ip)][:6]  # Hız için ilk 6 tekil IP

        for ip in public_ips:
            if ip in self._geoip_cache:
                enriched.append(self._geoip_cache[ip])
                continue

            info = {"ip": ip, "country": "UN", "isp": "Unknown ISP", "asn": ""}
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,as",
                    timeout=2.5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        asn_raw = data.get("as", "").split(" ")[0]
                        info = {
                            "ip": ip,
                            "country": data.get("countryCode", "UN"),
                            "isp": data.get("isp", "Unknown")[:28],
                            "asn": asn_raw,
                        }
            except Exception:
                pass

            self._geoip_cache[ip] = info
            enriched.append(info)

        return enriched

    def extract_high_entropy_secrets(self, text: str, existing_keys: List[str]) -> List[str]:
        secrets = []
        candidates = set(self.RE_TOKEN_CANDIDATE.findall(text))
        for cand in candidates:
            lower = cand.lower()
            if "http" in lower or ".com" in lower or ".onion" in lower or "example" in lower:
                continue
            if any(cand in k for k in existing_keys):
                continue
            entropy = self.shannon_entropy(cand)
            if entropy >= 4.25:
                secrets.append(f"{cand[:12]}...{cand[-6:]} (H={entropy:.2f})")
        return sorted(list(set(secrets)))[:15]

    def extract_threat_metadata(self, title: str, raw_content: str) -> Dict[str, str]:
        combined = f"{title}\n{raw_content}"
        country = "GLOBAL"
        c_match = self.RE_COUNTRY.search(combined)
        if c_match:
            country = c_match.group(1) or c_match.group(2) or "GLOBAL"

        actor = "Unknown"
        g_match = self.RE_GROUP.search(combined)
        if g_match:
            actor = (g_match.group(1) or g_match.group(2) or "Unknown").strip().upper()
        elif "urlhaus" in combined.lower():
            actor = "STEALER / BOTNET"
        elif "cisa" in combined.lower():
            actor = "APT / EXPLOIT"
        elif ".onion" in combined.lower():
            actor = "DARKWEB ACTOR"

        return {"victim_country": country, "threat_actor": actor}

    def analyze(self, raw_content: str, title: str, watch_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        combined_text = f"{title}\n{raw_content}"
        content_hash = self.compute_sha256(raw_content)

        cred_matches = self.RE_CREDENTIAL.findall(raw_content)
        credentials = [f"{email}:{pwd}" for email, pwd in cred_matches]

        emails = sorted(list(set(self.RE_EMAIL.findall(raw_content))))

        api_keys = []
        raw_key_values = []
        for key_type, pattern in self.API_KEY_PATTERNS.items():
            for match in pattern.findall(raw_content):
                raw_key_values.append(match)
                masked = match if len(match) <= 14 else f"{match[:8]}...{match[-4:]}"
                api_keys.append(f"[{key_type}] {masked}")

        cves = sorted(list(set(m.upper() for m in self.RE_CVE.findall(combined_text))))
        ips = sorted(list(set(self.RE_IPV4.findall(raw_content))))
        ibans = sorted(list(set(self.RE_IBAN.findall(raw_content))))
        domains = sorted(list(set(m.lower() for m in self.RE_DOMAIN.findall(raw_content))))

        # GeoIP & ASN Zenginleştirme
        ip_details = self.enrich_ips(ips)

        # Tehdit Aktörü ve Hedef Ülke Çıkarımı
        meta = self.extract_threat_metadata(title, raw_content)
        if meta["victim_country"] == "GLOBAL" and ip_details:
            first_cc = ip_details[0].get("country", "UN")
            if first_cc not in ("UN", ""):
                meta["victim_country"] = first_cc

        high_entropy_secrets = self.extract_high_entropy_secrets(raw_content, raw_key_values)

        matched_rules = []
        rule_boost_total = 0
        lower_combined = combined_text.lower()

        for rule in watch_rules:
            if not rule.get("is_active", True):
                continue
            kw = rule["keyword"].lower()
            if kw and kw in lower_combined:
                matched_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["rule_name"],
                    "keyword": rule["keyword"],
                    "category": rule["category"],
                    "risk_boost": rule["risk_boost"],
                })
                rule_boost_total += int(rule.get("risk_boost", 25))

        score = 10
        if credentials:
            score += min(35, 15 + len(credentials) * 5)
        if api_keys:
            score += 40
        if high_entropy_secrets:
            score += 15
        if cves:
            score += 20
        if ibans:
            score += 20
        if ips:
            score += 10
        if emails and not credentials:
            score += 10

        score += rule_boost_total
        risk_score = min(100, score)

        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        extracted_entities = {
            "credentials": credentials[:50],
            "emails": emails[:50],
            "api_keys": api_keys[:25],
            "high_entropy_secrets": high_entropy_secrets,
            "cves": cves,
            "ips": ips[:30],
            "ip_details": ip_details,
            "domains": domains[:30],
            "ibans": ibans[:20],
            "victim_country": meta["victim_country"],
            "threat_actor": meta["threat_actor"],
        }

        return {
            "content_hash": content_hash,
            "risk_score": risk_score,
            "severity": severity,
            "extracted_entities": extracted_entities,
            "matched_rules": matched_rules,
        }
