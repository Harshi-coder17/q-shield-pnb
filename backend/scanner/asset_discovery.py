# backend/scanner/asset_discovery.py
# Q-Shield — Asset Discovery Engine

import dns.resolver
import socket
import requests
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class AssetDiscovery:
    """
    Discovers public-facing assets for a domain
    """

    def __init__(self, domain: str):
        self.domain = domain.strip().lower()

    #  Step 1: DNS Resolution
    def resolve_dns(self) -> Dict:
        records = {}

        try:
            for rtype in ["A", "AAAA", "MX", "NS"]:
                try:
                    answers = dns.resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
        except Exception as e:
            logger.error(f"DNS resolution error: {e}")

        return records

    #  Step 2: Subdomain brute force (basic)
    def brute_subdomains(self) -> List[str]:
        common_subs = [
            "www", "mail", "api", "dev", "test", "staging",
            "admin", "portal", "vpn", "secure"
        ]

        found = []

        for sub in common_subs:
            full = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full)
                found.append(full)
            except:
                continue

        return found

    # Step 3: Certificate Transparency logs (crt.sh)
    def fetch_ct_logs(self) -> List[str]:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"

        found = set()

        try:
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name = entry.get("name_value", "")
                    for domain in name.split("\n"):
                        if self.domain in domain:
                            found.add(domain.strip())

        except Exception as e:
            logger.error(f"CT log error: {e}")

        return list(found)

    #  Main function
    def discover(self) -> Dict:
        dns_data = self.resolve_dns()
        brute = self.brute_subdomains()
        ct_logs = self.fetch_ct_logs()

        all_assets = list(set(brute + ct_logs))

        return {
            "domain": self.domain,
            "dns_records": dns_data,
            "subdomains_bruteforce": brute,
            "subdomains_ct_logs": ct_logs,
            "all_discovered_assets": all_assets,
        }


#  Quick test
if __name__ == "__main__":
    import json

    scanner = AssetDiscovery("google.com")
    result = scanner.discover()

    print(json.dumps(result, indent=2))