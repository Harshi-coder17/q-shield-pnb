
from datetime import datetime, timezone #normal timezone , date import kiya
from dateutil.parser import parse as parse_date # kissi bhi format ki date ko wale date ko import karaya
import logging #advanced version of printing 

logger = logging.getLogger(__name__) #apne print karane wali statement ko naam diya

QUANTUM_VULNERABLE_ALGORITHMS = [
    'RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'ECC', 'Diffie-Hellman', 'Elliptic Curve'
] # bure encryption methodologies
PQC_ALGORITHM_MARKERS = [
    'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON',
    'Dilithium', 'Kyber', 'SPHINCS', 'FIPS 203', 'FIPS 204', 'FIPS 205'
] # pqc wale algorithms
WEAK_CIPHER_KEYWORDS  = ['DES', '3DES', 'RC4', 'NULL', 'EXPORT', 'anon'] #eqasy to decode ciphers
CBC_CIPHER_KEYWORDS   = ['CBC'] #jodna blocks ko is cbc
STRONG_AEAD_KEYWORDS  = ['GCM', 'CCM', 'CHACHA20', 'POLY1305'] #authentication bhi daal do 

from datetime import datetime, timezone
from dateutil.parser import parse as parse_date
import logging

logger = logging.getLogger(__name__)

QUANTUM_VULNERABLE_ALGORITHMS = [
    'RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'ECC', 'Diffie-Hellman', 'Elliptic Curve'
]
PQC_ALGORITHM_MARKERS = [
    'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON',
    'Dilithium', 'Kyber', 'SPHINCS', 'FIPS 203', 'FIPS 204', 'FIPS 205'
]
WEAK_CIPHER_KEYWORDS  = ['DES', '3DES', 'RC4', 'NULL', 'EXPORT', 'anon']
CBC_CIPHER_KEYWORDS   = ['CBC']
STRONG_AEAD_KEYWORDS  = ['GCM', 'CCM', 'CHACHA20', 'POLY1305']

class QuantumScoringEngine:
    def score(self, tls_data: dict, cert_reuse: bool = False) -> dict:
        dim = {}
 
        # ── Dimension 1: TLS Version (25 pts) ──
        tls_ver = tls_data.get('tls_version', '')
        if   'TLSv1.3' in tls_ver or 'TLS 1.3' in tls_ver: dim['tls_version'] = 25
        elif 'TLSv1.2' in tls_ver or 'TLS 1.2' in tls_ver: dim['tls_version'] = 12
        else:                                                 dim['tls_version'] = 0
 
        # ── Dimension 2: Cipher Suite (20 pts) ──
        cipher      = tls_data.get('cipher_suite', '').upper()
        is_deprecated = any(k in cipher for k in WEAK_CIPHER_KEYWORDS)
        is_aead     = any(k in cipher for k in STRONG_AEAD_KEYWORDS)
        is_cbc      = any(k in cipher for k in CBC_CIPHER_KEYWORDS)
        if   is_deprecated: dim['cipher_suite'] = 0
        elif is_aead:       dim['cipher_suite'] = 20
        elif is_cbc:        dim['cipher_suite'] = 10
        else:               dim['cipher_suite'] = 5
 
        # ── Dimension 3: Key Exchange / Forward Secrecy (20 pts) ──
        ke = tls_data.get('key_exchange', '').upper()
        if   'ECDHE' in ke:                       dim['key_exchange'] = 20
        elif 'DHE' in ke and 'ECDH' not in ke:    dim['key_exchange'] = 20
        elif 'ECDH' in ke:                        dim['key_exchange'] = 12
        elif 'RSA' in ke:                         dim['key_exchange'] = 5
        else:                                      dim['key_exchange'] = 0
 
        # ── Dimension 4: Key Size (10 pts) ──
        ks = tls_data.get('cert_key_size', 0)
        if   ks >= 4096: dim['key_size'] = 10
        elif ks >= 3072: dim['key_size'] = 8
        elif ks >= 2048: dim['key_size'] = 7
        elif ks >= 1024: dim['key_size'] = 2
        else:            dim['key_size'] = 0
 
        # ── Dimension 5: Certificate Algorithm (15 pts) ──
        sig    = tls_data.get('cert_sig_algorithm', '')
        is_pqc = any(p.upper() in sig.upper() for p in PQC_ALGORITHM_MARKERS)
        is_ecdsa = 'ECDSA' in sig.upper()
        is_rsa   = 'RSA'   in sig.upper() and not is_pqc
        if   is_pqc:   dim['cert_algorithm'] = 15
        elif is_ecdsa: dim['cert_algorithm'] = 5
        elif is_rsa:   dim['cert_algorithm'] = 2.5
        else:          dim['cert_algorithm'] = 0
 
        # ── Dimension 6: Certificate Validity (5 pts) ──
        days_remaining = tls_data.get('cert_days_remaining')
        not_after_str  = tls_data.get('cert_not_after', '')
        if days_remaining is None and not_after_str:
            try:
                exp = parse_date(not_after_str)
                if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
                days_remaining = (exp - datetime.now(timezone.utc)).days
            except Exception:
                days_remaining = 0
        if   days_remaining is None: dim['cert_validity'] = 0
        elif days_remaining > 90:    dim['cert_validity'] = 5
        elif days_remaining > 30:    dim['cert_validity'] = 3
        elif days_remaining > 0:     dim['cert_validity'] = 2.5
        else:                        dim['cert_validity'] = 0
 
        # ── Dimension 7: Certificate Reuse Risk (5 pts) ──
        dim['cert_reuse'] = 0 if cert_reuse else 5
 
        # ── Total Score — use round() to handle float arithmetic on 2.5 values ──
        total = round(sum(dim.values()), 1)
 
        label  = self._assign_label(total)
        vulns  = self._detect_vulnerabilities(tls_data, sig, ks, tls_ver, cipher)
        recs   = self._generate_recommendations(dim, tls_data, sig, ks)
 
        return {
            'score': total, 'dimension_scores': dim, 'label': label,
            'vulnerabilities': vulns, 'recommendations': recs,
            'is_pqc': is_pqc,
            'is_quantum_vulnerable': any(
                v.upper() in sig.upper() for v in QUANTUM_VULNERABLE_ALGORITHMS),
        }
    def _assign_label(self, score: float) -> dict:
        """SRS Label Decision Flow (SRS Section 5.2)."""
        if   score >= 90: return {'text': 'Fully Quantum Safe',  'color': '#27AE60', 'icon': 'GREEN',  'tier': 'Elite'}
        elif score >= 60: return {'text': 'PQC Ready',           'color': '#F39C12', 'icon': 'YELLOW', 'tier': 'Standard'}
        elif score >= 30: return {'text': 'Quantum Vulnerable',  'color': '#E74C3C', 'icon': 'RED',    'tier': 'Legacy'}
        else:             return {'text': 'Critical',            'color': '#1C2833', 'icon': 'BLACK',  'tier': 'Critical'}
 
    def _detect_vulnerabilities(self, data, sig, ks, tls_ver, cipher) -> list:
        """FR-05: Flag quantum-vulnerable algorithms."""
        vulns = []
        for alg in QUANTUM_VULNERABLE_ALGORITHMS:
            if alg.upper() in sig.upper():
                vulns.append({'name': f'Quantum-Vulnerable Certificate Algorithm: {sig}',
                              'severity': 'HIGH', 'cve_reference': 'NIST PQC Migration Guide 2024',
                              'description': (f'{sig} is broken by Shor algorithm on a CRQC. Estimated timeline: 2030-2035.'),
                              'affected_component': 'Certificate Signature Algorithm'})
                break
        if any(v in tls_ver for v in ['TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']):
            vulns.append({'name': f'Deprecated Protocol Version: {tls_ver}', 'severity': 'HIGH',
                          'description': f'{tls_ver} is deprecated. Use TLS 1.3.',
                          'affected_component': 'TLS Protocol Version'})
        if 0 < ks < 2048:
            vulns.append({'name': f'Insufficient Key Size: {ks}-bit', 'severity': 'CRITICAL',
                          'description': f'{ks}-bit key provides < 80 bits of security. Minimum: 2048-bit RSA or 256-bit ECC.',
                          'affected_component': 'Certificate Public Key'})
        if any(k in cipher for k in WEAK_CIPHER_KEYWORDS):
            vulns.append({'name': 'Deprecated/Weak Cipher Suite', 'severity': 'CRITICAL',
                          'description': 'Cipher suite uses broken algorithms (DES/3DES/RC4).',
                          'affected_component': 'TLS Cipher Suite'})
        if not data.get('forward_secrecy', False):
            vulns.append({'name': 'No Forward Secrecy', 'severity': 'MEDIUM',
                          'description': 'Static key exchange without forward secrecy. Past sessions can be decrypted if key is compromised.',
                          'affected_component': 'Key Exchange Mechanism'})
        return vulns
 
    def _generate_recommendations(self, dim, data, sig, ks) -> list:
        """FR-11, FR-18: Generate specific PQC migration recommendations."""
        recs = []
        if dim['tls_version'] < 25:
            recs.append('IMMEDIATE: Upgrade to TLS 1.3. Disable TLS 1.0 and TLS 1.1 on all load balancers and web servers.')
        if dim['cipher_suite'] < 20:
            recs.append('Configure cipher suite priority: TLS_AES_256_GCM_SHA384 first, TLS_CHACHA20_POLY1305_SHA256 second. Remove CBC and RC4 suites.')
        if dim['key_exchange'] < 20:
            recs.append('Enable ECDHE as the only key exchange method. This provides forward secrecy.')
            recs.append('Phase 2 (PQC Migration): Implement ML-KEM-768 (Kyber) [FIPS 203] for post-quantum key encapsulation alongside ECDHE (hybrid approach).')
        if dim['cert_algorithm'] < 15:
            recs.append('PQC MIGRATION REQUIRED: Replace RSA/ECDSA certificate with ML-DSA-65 (Dilithium3) [FIPS 204] or SLH-DSA [FIPS 205]. Use a hybrid certificate during transition period.')
        if dim['key_size'] < 7:
            recs.append(f'Upgrade certificate key size to minimum 3072-bit RSA (current: {ks}-bit). Prefer 4096-bit for longer-lived certs.')
        if dim['cert_validity'] < 5:
            days = data.get('cert_days_remaining', 0)
            if days and days <= 0:
                recs.append('CRITICAL: Certificate has EXPIRED. Replace immediately.')
            else:
                recs.append(f'Certificate expires in {days} days. Renew now to avoid service disruption. Set up auto-renewal (Lets Encrypt / ACME).')
        if dim['cert_reuse'] == 0:
            recs.append('SECURITY RISK: Same certificate is used on multiple services. Issue unique certificates per service to limit blast radius.')
        return recs
 
if __name__ == '__main__':
    engine = QuantumScoringEngine()
    # Test 1: Modern config
    test_modern = {'tls_version': 'TLSv1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                   'key_exchange': 'ECDHE', 'forward_secrecy': True, 'cert_key_size': 4096,
                   'cert_sig_algorithm': 'ECDSA-SHA384', 'cert_days_remaining': 365}
    r1 = engine.score(test_modern, cert_reuse=False)
    print(f'Modern config: score={r1["score"]} label={r1["label"]["text"]}')
    # Test 2: Weak config
    test_weak = {'tls_version': 'TLSv1.0', 'cipher_suite': 'TLS_RSA_WITH_DES_CBC_SHA',
                 'key_exchange': 'RSA', 'forward_secrecy': False, 'cert_key_size': 1024,
                 'cert_sig_algorithm': 'RSA-SHA1', 'cert_days_remaining': -10}
    r2 = engine.score(test_weak, cert_reuse=True)
    print(f'Weak config: score={r2["score"]} label={r2["label"]["text"]}')
    print(f'Vulnerabilities: {len(r2["vulnerabilities"])} found')
