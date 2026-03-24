# backend/scanner/asset_discovery.py
# Q-Shield — Asset Discovery Engine
# Owner: Member 1 (Team Lead / TLS Scanner Engineer)
# SRS References: FR-15 (Asset Discovery), FR-16 (Asset Inventory)
 
import dns.resolver
import socket
import requests
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
 
logger = logging.getLogger(__name__)
 
BANKING_SUBDOMAINS = [
   'www', 'api', 'vpn', 'mail', 'portal', 'app', 'admin',
   'secure', 'gateway', 'login', 'netbanking', 'mobilebanking',
   'ib', 'retail', 'corporate', 'sme', 'ibank', 'onlinebanking',
   'atm', 'imps', 'neft', 'rtgs', 'upi', 'cards', 'loans',
   'smtp', 'webmail', 'owa', 'remote', 'extranet', 'partner',
   'download', 'upload', 'ftp', 'sftp', 'monitor', 'nagios',
   'proxy', 'postman', 'cos', 'recruit', 'hr', 'intranet'
]
 
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
class AssetDiscovery:
   """
   Discovers all public-facing assets for a given organization domain.
   Uses: DNS resolution, certificate transparency logs, common subdomain probing.
   All operations are passive and read-only.
   """
 
   def __init__(self, root_domain: str, max_workers: int = 10):
       self.root_domain       = root_domain.strip().lower()
       self.max_workers       = max_workers
       self.discovered_assets = []
       self.seen_hosts        = set()
 
   def discover_all(self) -> Dict:
       logger.info(f'Starting asset discovery for: {self.root_domain}')
       self._discover_dns_records()
       self._discover_via_cert_transparency()
       self._probe_common_subdomains()
       self._enrich_with_ip_data()
       return self._build_asset_inventory()
 
   def _discover_dns_records(self):
       resolver = dns.resolver.Resolver()
       resolver.timeout  = 5
       resolver.lifetime = 10
       for rtype in DNS_RECORD_TYPES:
           try:
               answers = resolver.resolve(self.root_domain, rtype)
               for rdata in answers:
                   value = str(rdata)
                   asset = {
                       'hostname': self.root_domain, 'record_type': rtype,
                       'value': value, 'source': 'DNS',
                       'asset_type': self._classify_by_record(rtype, value)
                   }
                   if rtype == 'A':    asset['ipv4'] = value
                   elif rtype == 'AAAA': asset['ipv6'] = value
                   self._add_asset(asset)
           except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                   dns.resolver.NoNameservers, dns.exception.Timeout):
               pass
           except Exception as e:
               logger.debug(f'DNS {rtype} lookup failed: {e}')
 
   def _discover_via_cert_transparency(self):
       """Queries crt.sh — free public certificate transparency log. Passive read-only."""
       try:
           url  = f'https://crt.sh/?q=%.{self.root_domain}&output=json'
           resp = requests.get(url, timeout=15)
           if resp.status_code != 200: return
           entries    = resp.json()
           seen_names = set()
           for entry in entries[:200]:  # cap at 200 CT log entries
               raw_name = entry.get('name_value', '')
               for name in raw_name.split('\n'):
                   name = name.strip().lower()
                   if name.startswith('*.'): name = name[2:]
                   if name and name.endswith(self.root_domain) and name not in seen_names:
                        seen_names.add(name)

                        if '@' in name:
                            asset_type = 'Email'
                        else:
                            asset_type = 'Domain'

                        self._add_asset({
                            'hostname': name,
                            'record_type': 'CT-LOG',
                            'value': name,
                            'source': 'crt.sh',
                            'ssl_cn': entry.get('common_name', ''),
                            'ssl_issuer': entry.get('issuer_name', ''),
                            'ssl_valid_from': entry.get('not_before', ''),
                            'asset_type': asset_type
                        })
       except Exception as e:
           logger.warning(f'crt.sh lookup failed: {e}')
 
   def _probe_common_subdomains(self):
       candidates = [f'{sub}.{self.root_domain}'
                     for sub in BANKING_SUBDOMAINS
                     if f'{sub}.{self.root_domain}' not in self.seen_hosts]
 
       def probe(fqdn):
           try:
               ip = socket.gethostbyname(fqdn)
               return {'hostname': fqdn, 'ipv4': ip, 'record_type': 'A',
                       'source': 'subdomain-probe', 'asset_type': 'Domain'}
           except socket.gaierror:
               return None
 
       with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
           futures = {ex.submit(probe, c): c for c in candidates}
           for future in as_completed(futures):
               result = future.result()
               if result: self._add_asset(result)
 
   def _enrich_with_ip_data(self):
       for asset in self.discovered_assets:
           ip = asset.get('ipv4', '')
           if not ip: continue
           try:
               asset['reverse_dns'] = socket.gethostbyaddr(ip)[0]
           except Exception:
               asset['reverse_dns'] = ''
           try:
               s = socket.create_connection((ip, 443), timeout=3)
               s.close()
               asset['port_443_open'] = True
               asset['asset_type']    = 'Web Server'
           except Exception:
               asset['port_443_open'] = False
 
   def _classify_by_record(self, rtype, value) -> str:
       if rtype in ('A', 'AAAA'): return 'Server'
       if rtype == 'MX':          return 'Mail Server'
       if rtype == 'NS':          return 'Nameserver'
       return 'Other'
 
   def _add_asset(self, asset: dict):
       key = asset.get('hostname', '') + asset.get('value', '')
       if key not in self.seen_hosts:
           self.seen_hosts.add(key)
           self.discovered_assets.append(asset)
 
   def _build_asset_inventory(self) -> dict:
       domains    = [a for a in self.discovered_assets
                     if a.get('source') in ('DNS', 'crt.sh', 'subdomain-probe')
                     and a.get('record_type') in ('A', 'AAAA', 'CT-LOG')]
       ips        = [a for a in self.discovered_assets
                     if a.get('record_type') == 'A' and a.get('ipv4')]
       ssl_certs  = [a for a in self.discovered_assets if a.get('source') == 'crt.sh']
       return {'root_domain': self.root_domain,
               'total_discovered': len(self.discovered_assets),
               'domains': domains, 'ip_addresses': ips,
               'ssl_certs': ssl_certs, 'all_assets': self.discovered_assets}
 
if __name__ == '__main__':
    import json

    disco  = AssetDiscovery('pnb.co.in')
    result = disco.discover_all()

    print(f"Discovered {result['total_discovered']} assets")

    shown = 0

    # 1️⃣ Show DNS first
    for a in result['domains']:
        if shown >= 10:
            break

        ip = a.get('ipv4')

        if a.get('source') == 'DNS' and ip:
            print(f"  Domain: {a['hostname']} → {ip} [DNS]")
            shown += 1


    # 2️⃣ Then subdomain probe
    for a in result['domains']:
        if shown >= 10:
            break

        ip = a.get('ipv4')

        if a.get('source') == 'subdomain-probe' and ip:
            print(f"  Domain: {a['hostname']} → {ip} [Probe]")
            shown += 1


    # 3️⃣ Then CT logs
    for a in result['domains']:
        if shown >= 10:
            break

        if a.get('source') == 'crt.sh':
            print(f"  Domain: {a['hostname']} → [CT Log]")
            shown += 1