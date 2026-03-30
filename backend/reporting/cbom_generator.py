# backend/reporting/cbom_generator.py
from datetime import datetime, timezone
import csv, io, json
import logging
 
logger = logging.getLogger(__name__)
 
# ── Security strength lookup per NIST SP 800-57 Table 2 ──
# Used for Cert-In Annexure-A 'classical_security_bits' field
KEY_SECURITY_BITS = {
    1024: 80,   # RSA-1024 — below acceptable threshold
    2048: 112,  # RSA-2048 — current minimum standard
    3072: 128,  # RSA-3072 — recommended
    4096: 140,  # RSA-4096 — strong
    7680: 192,  # RSA-7680 — equivalent to AES-192
    15360: 256, # RSA-15360 — equivalent to AES-256 (future-proof classical)
    256: 128,   # ECDSA P-256 — 128-bit security
    384: 192,   # ECDSA P-384 — 192-bit security
    521: 260,   # ECDSA P-521 — 260-bit security
}
 
PQC_ALGORITHM_MARKERS = ['ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON', 'Dilithium', 'Kyber', 'SPHINCS']
CLASSICAL_VULNERABLE  = ['RSA', 'ECDSA', 'ECDH', 'DH', 'DSA']
 
CBOM_SCHEMA_VERSION = '1.0'
TOOL_NAME           = 'Q-Shield v1.0 — PNB Cybersecurity Hackathon 2026'
 
class CBOMGenerator:
    """
    Generates a Cryptographic Bill of Materials from scan results.
    Complies with Cert-In Circular CERT-In/2022/SECY-007 Annexure-A.
    All 22 required fields are populated.
    """
 
    def generate_cbom(self, scan_results: list) -> dict:
        certificates = []
        keys         = {}
        algorithms   = {}
        protocols    = {}

        dependencies       = []
        algorithm_usage    = {}
        certificate_usage  = {}
        pqc_readiness_map  = {}
        risk_summary       = {
            'quantum_vulnerable_assets': 0,
            'weak_cipher_assets': 0,
            'no_forward_secrecy': 0
        }

        for scan in scan_results:
            if not scan:
                continue

            hostname = scan.get('hostname', 'unknown')

            # EXISTING LOGIC (UNCHANGED)
            self._add_certificate(certificates, scan, hostname)
            self._add_key(keys, scan, hostname)
            self._add_algorithm(algorithms, scan)
            self._add_protocol(protocols, scan)

            # ────────────────────────────
            #  DEPENDENCY GRAPH
            # ─────────────────────────────
            dependencies.append({
                'hostname': hostname,
                'certificate_fp': scan.get('cert_sha256_fp'),
                'algorithm': scan.get('cert_sig_algorithm'),
                'cipher': scan.get('cipher_suite'),
                'tls_version': scan.get('tls_version')
            })

            # ─────────────────────────────
            #  ALGORITHM USAGE TRACKING
            # ─────────────────────────────
            sig = scan.get('cert_sig_algorithm', 'unknown')
            algorithm_usage[sig] = algorithm_usage.get(sig, 0) + 1

            # ─────────────────────────────
            #  CERTIFICATE REUSE DETECTION
            # ─────────────────────────────
            cert_fp = scan.get('cert_sha256_fp')
            if cert_fp:
                if cert_fp not in certificate_usage:
                    certificate_usage[cert_fp] = []
                certificate_usage[cert_fp].append(hostname)

            # ─────────────────────────────
            #  PQC READINESS PER HOST
            # ─────────────────────────────
            is_pqc = scan.get('is_pqc_algorithm', False)
            pqc_readiness_map[hostname] = {
                'is_pqc_ready': is_pqc,
                'migration_required': not is_pqc,
                'current_algorithm': sig
            }

            # ─────────────────────────────
            #  RISK AGGREGATION
            # ─────────────────────────────
            if any(v in sig for v in CLASSICAL_VULNERABLE):
                risk_summary['quantum_vulnerable_assets'] += 1

            if scan.get('is_weak_cipher'):
                risk_summary['weak_cipher_assets'] += 1

            if not scan.get('forward_secrecy'):
                risk_summary['no_forward_secrecy'] += 1

        # ─────────────────────────────
        #  CERTIFICATE REUSE FILTER
        # ─────────────────────────────
        certificate_reuse = {
            fp: hosts for fp, hosts in certificate_usage.items() if len(hosts) > 1
        }

        return {
            'cbom_version':  CBOM_SCHEMA_VERSION,
            'generated_at':  datetime.now(timezone.utc).isoformat(),
            'tool_name':     TOOL_NAME,
            'scope':         'PNB Banking Infrastructure TLS Assessment',

            # EXISTING (UNCHANGED)
            'certificates':  certificates,
            'keys':          list(keys.values()),
            'algorithms':    list(algorithms.values()),
            'protocols':     list(protocols.values()),

            # INTELLIGENCE LAYER
            'dependencies':        dependencies,
            'algorithm_usage':     algorithm_usage,
            'certificate_reuse':   certificate_reuse,
            'pqc_readiness':       pqc_readiness_map,
            'risk_summary':        risk_summary,

            'summary': {
                'total_assets':   len(scan_results),
                'total_certs':    len(certificates),
                'total_keys':     len(keys),
                'total_algs':     len(algorithms),
                'total_protocols':len(protocols),
                'pqc_count':      sum(1 for s in scan_results if s.get('is_pqc_algorithm')),
                'quantum_vulnerable': sum(
                    1 for s in scan_results
                    if any(v in str(s.get('cert_sig_algorithm','')) for v in CLASSICAL_VULNERABLE)
                ),
                
                'most_used_algorithm': max(algorithm_usage, key=algorithm_usage.get) if algorithm_usage else None,
                'reused_certificates': len(certificate_reuse)
            }
        }
    def _add_certificate(self, cert_list: list, scan: dict, hostname: str):
        """Cert-In Annexure-A Certificate section — 9 fields."""
        cert_list.append({
            'hostname':              hostname,
            'cert_subject':          scan.get('cert_subject',          ''),
            'cert_issuer':           scan.get('cert_issuer',            ''),
            'cert_not_before':       scan.get('cert_not_before',        ''),
            'cert_not_after':        scan.get('cert_not_after',         ''),
            'cert_days_remaining':   scan.get('cert_days_remaining',    0),
            'sig_algorithm':         scan.get('cert_sig_algorithm',     ''),
            'sig_oid':               scan.get('cert_sig_oid',           ''),
            'cert_sha1_fingerprint': scan.get('cert_sha1_fp',           ''),
            'cert_sha256_fingerprint': scan.get('cert_sha256_fp',       ''),
            'cert_verified':         scan.get('cert_verified',          True),
            'cert_san':              scan.get('cert_san',               []),
        })
 
    def _add_key(self, keys: dict, scan: dict, hostname: str):
        """Cert-In Annexure-A Public Key section — 4 fields."""
        ks      = scan.get('cert_key_size', 0)
        kt      = scan.get('cert_key_type', 'Unknown')
        key_key = f'{kt}-{ks}'
        if key_key not in keys:
            # classical_security_bits — closest match in NIST SP800-57 table
            sec_bits = KEY_SECURITY_BITS.get(ks, 0)
            if not sec_bits and ks:
                candidates = [k for k in KEY_SECURITY_BITS if k <= ks]
                sec_bits   = KEY_SECURITY_BITS[max(candidates)] if candidates else 0
            sig_name     = scan.get('cert_sig_algorithm', '')
            is_pqc       = any(p.upper() in sig_name.upper() for p in PQC_ALGORITHM_MARKERS)
            is_vuln      = any(v.upper() in sig_name.upper() for v in CLASSICAL_VULNERABLE)
            keys[key_key] = {
                'key_type':              kt,
                'key_size_bits':         ks,
                'classical_security_bits': sec_bits,
                'quantum_resistance':    'YES' if is_pqc else 'NO',
                'quantum_vulnerability': 'YES' if is_vuln else 'NO',
                'example_hostnames':     [hostname],
            }
        elif hostname not in keys[key_key]['example_hostnames']:
            keys[key_key]['example_hostnames'].append(hostname)
 
    def _add_algorithm(self, algorithms: dict, scan: dict):
        """Cert-In Annexure-A Algorithm section — 5 fields."""
        sig_oid  = scan.get('cert_sig_oid', '')
        sig_name = scan.get('cert_sig_algorithm', '')
        # Deduplicate by OID (preferred) or algorithm name
        alg_key  = sig_oid if sig_oid else sig_name
        if alg_key and alg_key not in algorithms:
            is_pqc  = any(p.upper() in sig_name.upper() for p in PQC_ALGORITHM_MARKERS)
            is_vuln = any(v.upper() in sig_name.upper() for v in CLASSICAL_VULNERABLE)
            standard = ''
            if 'FIPS 203' in sig_name: standard = 'NIST FIPS 203'
            elif 'FIPS 204' in sig_name: standard = 'NIST FIPS 204'
            elif 'FIPS 205' in sig_name: standard = 'NIST FIPS 205'
            elif 'FALCON'   in sig_name.upper(): standard = 'NIST Round 4'
            elif 'RSA'      in sig_name.upper(): standard = 'PKCS#1 v2.2'
            elif 'ECDSA'    in sig_name.upper(): standard = 'FIPS 186-4'
            algorithms[alg_key] = {
                'algorithm_name':    sig_name,
                'standard':          standard,
                'oid':               sig_oid,
                'is_pqc':            is_pqc,
                'vulnerability_risk': 'NONE (PQC)' if is_pqc else ('HIGH' if is_vuln else 'UNKNOWN'),
            }
 
    def _add_protocol(self, protocols: dict, scan: dict):
        """Cert-In Annexure-A Protocol section — 4 fields."""
        tls_ver = scan.get('tls_version', '')
        cipher  = scan.get('cipher_suite', '')
        ke      = scan.get('key_exchange', '')
        fs      = scan.get('forward_secrecy', False)
        proto_key = f'{tls_ver}||{cipher}'  # composite dedup key
        if proto_key not in protocols:
            protocols[proto_key] = {
                'protocol_version': tls_ver,
                'cipher_suite':     cipher,
                'key_exchange':     ke,
                'forward_secrecy':  fs,
            }
    def to_csv(self, cbom: dict) -> str:
        """Generate CSV export of CBOM for Cert-In submission."""
        output  = io.StringIO()
        # Write certificate section
        output.write('=== CERTIFICATES ===\n')
        cert_fields = [
            'hostname','cert_subject','cert_issuer','cert_not_before','cert_not_after',
            'cert_days_remaining','sig_algorithm','sig_oid','cert_sha1_fingerprint','cert_verified'
        ]
        w = csv.DictWriter(output, fieldnames=cert_fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(cbom.get('certificates', []))
        # Write keys section
        output.write('\n=== PUBLIC KEYS ===\n')
        key_fields = ['key_type','key_size_bits','classical_security_bits','quantum_resistance']
        wk = csv.DictWriter(output, fieldnames=key_fields, extrasaction='ignore')
        wk.writeheader()
        wk.writerows(cbom.get('keys', []))
        # Write algorithms section
        output.write('\n=== ALGORITHMS ===\n')
        alg_fields = ['algorithm_name','standard','oid','is_pqc','vulnerability_risk']
        wa = csv.DictWriter(output, fieldnames=alg_fields, extrasaction='ignore')
        wa.writeheader()
        wa.writerows(cbom.get('algorithms', []))
        # Write protocols section
        output.write('\n=== PROTOCOLS ===\n')
        proto_fields = ['protocol_version','cipher_suite','key_exchange','forward_secrecy']
        wp = csv.DictWriter(output, fieldnames=proto_fields, extrasaction='ignore')
        wp.writeheader()
        wp.writerows(cbom.get('protocols', []))
        return output.getvalue()
 
if __name__ == '__main__':
    # Quick test with mock data
    mock = [{'hostname': 'test.pnb.co.in', 'cert_subject': 'CN=test.pnb.co.in',
             'cert_issuer': 'DigiCert', 'cert_not_before': '2024-01-01', 'cert_not_after': '2026-01-01',
             'cert_days_remaining': 280, 'cert_sig_algorithm': 'RSA-SHA256',
             'cert_sig_oid': '1.2.840.113549.1.1.11', 'cert_key_size': 2048,
             'cert_key_type': 'RSA', 'cert_sha1_fp': 'AA:BB:CC', 'cert_sha256_fp': 'DD:EE:FF',
             'tls_version': 'TLSv1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384',
             'key_exchange': 'ECDHE', 'forward_secrecy': True, 'is_pqc_algorithm': False}]
    gen  = CBOMGenerator()
    cbom = gen.generate_cbom(mock)
    print('CBOM generated:')
    print(f'  Certificates: {len(cbom["certificates"])}')
    print(f'  Keys:         {len(cbom["keys"])}')
    print(f'  Algorithms:   {len(cbom["algorithms"])}')
    print(f'  Protocols:    {len(cbom["protocols"])}')
    print('CSV preview:')
    print(gen.to_csv(cbom)[:300])
