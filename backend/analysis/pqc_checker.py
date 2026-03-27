PQC_OID_REGISTRY = {
    # ML-KEM (Kyber) — FIPS 203
    '2.16.840.1.101.3.4.4.1': {'name': 'ML-KEM-512',  'standard': 'FIPS 203'},
    '2.16.840.1.101.3.4.4.2': {'name': 'ML-KEM-768',  'standard': 'FIPS 203'},
    '2.16.840.1.101.3.4.4.3': {'name': 'ML-KEM-1024', 'standard': 'FIPS 203'},
    # ML-DSA (Dilithium) — FIPS 204
    '2.16.840.1.101.3.4.3.17': {'name': 'ML-DSA-44', 'standard': 'FIPS 204'},
    '2.16.840.1.101.3.4.3.18': {'name': 'ML-DSA-65', 'standard': 'FIPS 204'},
    '2.16.840.1.101.3.4.3.19': {'name': 'ML-DSA-87', 'standard': 'FIPS 204'},
    # SLH-DSA (SPHINCS+) — FIPS 205
    '2.16.840.1.101.3.4.3.20': {'name': 'SLH-DSA-SHA2-128s', 'standard': 'FIPS 205'},
    '2.16.840.1.101.3.4.3.21': {'name': 'SLH-DSA-SHA2-192s', 'standard': 'FIPS 205'},
    '2.16.840.1.101.3.4.3.22': {'name': 'SLH-DSA-SHA2-256s', 'standard': 'FIPS 205'},
    # FALCON — NIST Round 4
    '1.3.9999.3.1': {'name': 'FALCON-512',  'standard': 'NIST Round 4'},
    '1.3.9999.3.4': {'name': 'FALCON-1024', 'standard': 'NIST Round 4'},
}
 
CLASSICAL_VULNERABLE = {
    'RSA':   {'risk': 'Broken by Shor algorithm', 'severity': 'HIGH'},
    'ECDSA': {'risk': 'Broken by Shor algorithm', 'severity': 'HIGH'},
    'ECDH':  {'risk': 'Broken by Shor algorithm', 'severity': 'HIGH'},
    'DH':    {'risk': 'Broken by Shor algorithm (DLP)', 'severity': 'HIGH'},
    'DSA':   {'risk': 'Broken by Shor algorithm', 'severity': 'HIGH'},
}
 
class PQCChecker:
    def check(self, tls_data: dict) -> dict:
        sig_oid  = tls_data.get('cert_sig_oid', '')
        sig_name = tls_data.get('cert_sig_algorithm', '')
        pqc_by_oid  = PQC_OID_REGISTRY.get(sig_oid)
        pqc_by_name = None
        for oid, info in PQC_OID_REGISTRY.items():
            if info['name'].upper().split('-')[0] in sig_name.upper():
                pqc_by_name = info; break
        is_pqc  = pqc_by_oid is not None or pqc_by_name is not None
        pqc_info = pqc_by_oid or pqc_by_name
        vuln_info = None
        for alg, info in CLASSICAL_VULNERABLE.items():
            if alg in sig_name.upper():
                vuln_info = {'algorithm': alg, **info}; break
        return {
            'is_pqc': is_pqc,
            'pqc_algorithm': pqc_info.get('name') if pqc_info else None,
            'pqc_standard':  pqc_info.get('standard') if pqc_info else None,
            'is_quantum_vulnerable': vuln_info is not None,
            'vulnerability': vuln_info,
            'detected_oid': sig_oid, 'detected_algorithm': sig_name,
        }
