PQC_OID_REGISTRY = {
    # ML-KEM (Kyber) — FIPS 203 a key encapsulation mechanism (used for key exchange, not signing)
    '2.16.840.1.101.3.4.4.1': {'name': 'ML-KEM-512',  'standard': 'FIPS 203'},  #level 1
    '2.16.840.1.101.3.4.4.2': {'name': 'ML-KEM-768',  'standard': 'FIPS 203'},  #level 3
    '2.16.840.1.101.3.4.4.3': {'name': 'ML-KEM-1024', 'standard': 'FIPS 203'},  #level 5
    # ML-DSA (Dilithium) — FIPS 204 a digital signature algorithm (used in certificates)
    '2.16.840.1.101.3.4.3.17': {'name': 'ML-DSA-44', 'standard': 'FIPS 204'},
    '2.16.840.1.101.3.4.3.18': {'name': 'ML-DSA-65', 'standard': 'FIPS 204'},
    '2.16.840.1.101.3.4.3.19': {'name': 'ML-DSA-87', 'standard': 'FIPS 204'},
    # SLH-DSA (SPHINCS+) — FIPS 205  a hash-based signature scheme.
    '2.16.840.1.101.3.4.3.20': {'name': 'SLH-DSA-SHA2-128s', 'standard': 'FIPS 205'},
    '2.16.840.1.101.3.4.3.21': {'name': 'SLH-DSA-SHA2-192s', 'standard': 'FIPS 205'},
    '2.16.840.1.101.3.4.3.22': {'name': 'SLH-DSA-SHA2-256s', 'standard': 'FIPS 205'},
    # FALCON — NIST Round 4 a lattice-based signature algorithm (not yet fully standardized).
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
        sig_oid  = tls_data.get('cert_sig_oid', '') # safely reads from the dict — returns '' instead of raising KeyError if the key is missing. 
        sig_name = tls_data.get('cert_sig_algorithm', '')
        
        pqc_by_oid  = PQC_OID_REGISTRY.get(sig_oid)         #If sig_oid exactly matches a key in the registry, you get that algorithm's info dict back. If not, you get None.


        # This is the fallback for when the OID is missing or unrecognized.
        pqc_by_name = None
        for oid, info in PQC_OID_REGISTRY.items(): # passes (key, value) pairs, here (oid_string, info_dict)
            family = '-'.join(info['name'].upper().split('-')[:2])  # 'ML-KEM', 'ML-DSA', 'SLH-DSA'
            if family in sig_name.upper():
                pqc_by_name = info; break
            

        is_pqc  = pqc_by_oid is not None or pqc_by_name is not None
        pqc_info = pqc_by_oid or pqc_by_name
        # track how confident we are
        if pqc_by_oid:
            confidence = 'HIGH'    # OID is exact, binary match
        elif pqc_by_name:
            confidence = 'MEDIUM'  # name matched but could still be a fake/custom algo
        else:
            confidence = 'NONE'

        vuln_info = None
        for alg, info in CLASSICAL_VULNERABLE.items():
            if alg in sig_name.upper():
                vuln_info = {'algorithm': alg, **info}; break
        
        

        # --- CONFLICT GUARD ---
        # if OID confirmed PQC, don't also flag as vulnerable
        if pqc_by_oid and vuln_info:
            vuln_info = None

        # --- CERT ALGORITHM SCORE ---
        if is_pqc:
            cert_algo_score = 15 if confidence == 'HIGH' else 7
        elif pqc_info is None and 'ECDSA' in sig_name.upper():
            cert_algo_score = 5
        elif pqc_info is None and 'RSA' in sig_name.upper():
            cert_algo_score = 2.5
        else:
            cert_algo_score = 0

        return {
            'is_pqc': is_pqc,
            'confidence': confidence,
            'cert_algo_score':cert_algo_score,
            'pqc_algorithm': pqc_info.get('name') if pqc_info else None,
            'pqc_standard':  pqc_info.get('standard') if pqc_info else None,
            'is_quantum_vulnerable': vuln_info is not None,
            'vulnerability': vuln_info,
            'detected_oid': sig_oid, 'detected_algorithm': sig_name,
        }



test_cases = [
    # --- THE TWO BUGS WE FIXED ---
    {
        'label':    'BUG1 FIX — ML-something (was matching ML-KEM)',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'ML-with-SHA256'},
        'expect':   {'is_pqc': False, 'confidence': 'NONE'}
    },
    {
        'label':    'BUG2 FIX — SLH-FAKE-999 (was marked safe)',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'SLH-FAKE-999'},
        'expect':   {'is_pqc': False, 'confidence': 'NONE'}
    },

    # --- CONFIDENCE: HIGH (OID path) ---
    {
        'label':    'HIGH confidence — valid ML-DSA OID only',
        'input':    {'cert_sig_oid': '2.16.840.1.101.3.4.3.17', 'cert_sig_algorithm': ''},
        'expect':   {'is_pqc': True, 'confidence': 'HIGH', 'cert_algo_score': 15}
    },
    {
        'label':    'HIGH confidence — valid FALCON OID only',
        'input':    {'cert_sig_oid': '1.3.9999.3.1', 'cert_sig_algorithm': ''},
        'expect':   {'is_pqc': True, 'confidence': 'HIGH', 'cert_algo_score': 15}
    },

    # --- CONFIDENCE: MEDIUM (name path) ---
    {
        'label':    'MEDIUM confidence — ML-KEM in name, no OID',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'ML-KEM-768'},
        'expect':   {'is_pqc': True, 'confidence': 'MEDIUM', 'cert_algo_score': 7}
    },
    {
        'label':    'MEDIUM confidence — SLH-DSA in name, no OID',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'SLH-DSA-SHA2-128s'},
        'expect':   {'is_pqc': True, 'confidence': 'MEDIUM', 'cert_algo_score': 7}
    },

    # --- CONFLICT GUARD ---
    {
        'label':    'CONFLICT GUARD — PQC OID + RSA in name (vuln should be cleared)',
        'input':    {'cert_sig_oid': '2.16.840.1.101.3.4.3.17', 'cert_sig_algorithm': 'RSA-SHA256'},
        'expect':   {'is_pqc': True, 'confidence': 'HIGH', 'is_quantum_vulnerable': False}
    },

    # --- OID PRIORITY ---
    {
        'label':    'OID PRIORITY — OID=ML-KEM-512, name=ML-DSA-65',
        'input':    {'cert_sig_oid': '2.16.840.1.101.3.4.4.1', 'cert_sig_algorithm': 'ML-DSA-65'},
        'expect':   {'is_pqc': True, 'confidence': 'HIGH', 'pqc_algorithm': 'ML-KEM-512'}
    },

    # --- CLASSICAL VULNERABLE ---
    {
        'label':    'CLASSICAL — ECDSA (should NOT trigger DSA too)',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'ECDSA-SHA256'},
        'expect':   {'is_pqc': False, 'is_quantum_vulnerable': True, 'cert_algo_score': 5}
    },
    {
        'label':    'CLASSICAL — RSA-SHA256',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'RSA-SHA256'},
        'expect':   {'is_pqc': False, 'is_quantum_vulnerable': True, 'cert_algo_score': 2.5}
    },

    # --- EDGE CASES ---
    {
        'label':    'EDGE — empty input',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': ''},
        'expect':   {'is_pqc': False, 'confidence': 'NONE', 'is_quantum_vulnerable': False}
    },
    {
        'label':    'EDGE — missing keys entirely',
        'input':    {},
        'expect':   {'is_pqc': False, 'confidence': 'NONE'}
    },
    {
        'label':    'EDGE — lowercase ecdsa (case handling)',
        'input':    {'cert_sig_oid': '', 'cert_sig_algorithm': 'ecdsa-with-sha256'},
        'expect':   {'is_pqc': False, 'is_quantum_vulnerable': True}
    },
]

# ============================================================
# RUNNER
# ============================================================

checker = PQCChecker()
passed  = 0
failed  = 0

print(f"\n{'#':<3} {'Label':<55} {'PASS/FAIL':<10} {'confidence':<10} {'is_pqc':<8} {'score':<7} {'vuln?':<7} {'notes'}")
print("-" * 140)

for i, tc in enumerate(test_cases, 1):
    r      = checker.check(tc['input'])
    expect = tc['expect']

    # check every key defined in expect against actual result
    mismatches = [
        f"{k}: expected {v!r} got {r.get(k)!r}"
        for k, v in expect.items()
        if r.get(k) != v
    ]

    ok = len(mismatches) == 0
    if ok: passed += 1
    else:  failed += 1

    status = 'PASS' if ok else 'FAIL'
    notes  = ' | '.join(mismatches) if mismatches else ''

    print(
        f"{i:<3} "
        f"{tc['label']:<55} "
        f"{status:<10} "
        f"{r['confidence']:<10} "
        f"{str(r['is_pqc']):<8} "
        f"{str(r['cert_algo_score']):<7} "
        f"{str(r['is_quantum_vulnerable']):<7} "
        f"{notes}"
    )

print("-" * 140)
print(f"\nResult: {passed}/{len(test_cases)} passed", "✓" if failed == 0 else f"— {failed} FAILED")