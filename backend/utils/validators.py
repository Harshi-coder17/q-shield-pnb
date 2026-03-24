# backend/utils/validators.py
# Q-Shield — Input Validation & Anti-SSRF Protection
# Owner: Member 1 (Team Lead / TLS Scanner Engineer)
# SRS References: FR-01 (Target Input), SRS Section 8 (Security)
 
import re, socket
from urllib.parse import urlparse
 
# Block all private / reserved IP ranges (SRS: scan public-facing only)
BLOCKED_PREFIXES = [
   '10.', '192.168.', '127.', '0.',
   '169.254.',   # Link-local
   '100.64.',    # CGNAT
   '::1',        # IPv6 loopback
   'fc00:', 'fd', # IPv6 private
]
 
def _is_private_172(ip: str) -> bool:
   try:
       parts = ip.split('.')
       if len(parts) < 2: return False
       return int(parts[0]) == 172 and 16 <= int(parts[1]) <= 31
   except: return False
 
DOMAIN_REGEX = re.compile(
   r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
 
def validate_target(raw: str) -> dict:
   """
   Validates and normalizes a scan target.
   Returns {'valid': True, 'hostname': ..., 'url': ...}
   or {'valid': False, 'error': 'reason'}
   """
   if not raw or not isinstance(raw, str):
       return {'valid': False, 'error': 'Empty input'}
   raw = raw.strip()
   if len(raw) > 253:
       return {'valid': False, 'error': 'Target too long (max 253 chars)'}
   if not raw.startswith(('http://', 'https://')):
       raw = 'https://' + raw
   try:
       parsed   = urlparse(raw)
       hostname = parsed.hostname
   except Exception:
       return {'valid': False, 'error': 'Could not parse URL'}
   if not hostname:
       return {'valid': False, 'error': 'No hostname found in URL'}
   try:
       resolved_ip = socket.gethostbyname(hostname)
   except socket.gaierror:
       return {'valid': False, 'error': f'Cannot resolve hostname: {hostname}'}
   for prefix in BLOCKED_PREFIXES:
       if resolved_ip.startswith(prefix):
           return {'valid': False, 'error': f'Private IP range blocked: {resolved_ip}'}
   if _is_private_172(resolved_ip):
       return {'valid': False, 'error': f'Private IP range blocked: {resolved_ip}'}
   if not DOMAIN_REGEX.match(hostname) and not _is_valid_public_ip(resolved_ip):
       return {'valid': False, 'error': 'Invalid domain format'}
   return {'valid': True, 'hostname': hostname, 'url': raw, 'resolved_ip': resolved_ip}
 
def _is_valid_public_ip(ip: str) -> bool:
   try: socket.inet_aton(ip); return True
   except: return False
 
def validate_batch_file(filepath: str) -> list:
   results = []
   with open(filepath, 'r') as f:
       for line in f:
           line = line.strip()
           if line and not line.startswith('#'):
               results.append({'raw': line, **validate_target(line)})
   return results
# ── Quick test — run directly ──
if __name__ == '__main__':
    test_inputs = [
        "google.com",
        "https://example.com",
        "localhost",
        "127.0.0.1",
        "192.168.1.1"
    ]

    for t in test_inputs:
        result = validate_target(t)
        print(f"\nInput: {t}")
        print(result)