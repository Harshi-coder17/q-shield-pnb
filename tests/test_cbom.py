# tests/test_cbom.py

import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
 
from reporting.cbom_generator import CBOMGenerator
 
@pytest.fixture
def generator():
    return CBOMGenerator()
 
@pytest.fixture
def mock_scan():
    return {
        'hostname': 'test.pnb.co.in', 'cert_subject': 'CN=test.pnb.co.in',
        'cert_issuer': 'DigiCert SHA2', 'cert_not_before': '2024-01-01T00:00:00+00:00',
        'cert_not_after':  '2026-01-01T00:00:00+00:00', 'cert_days_remaining': 280,
        'cert_sig_algorithm': 'RSA-SHA256', 'cert_sig_oid': '1.2.840.113549.1.1.11',
        'cert_key_size': 2048, 'cert_key_type': 'RSA',
        'cert_sha1_fp': 'AA:BB:CC:DD:EE', 'cert_sha256_fp': 'FF:00:11:22',
        'cert_san': ['test.pnb.co.in', 'www.test.pnb.co.in'],
        'tls_version': 'TLSv1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384',
        'key_exchange': 'ECDHE', 'forward_secrecy': True, 'is_pqc_algorithm': False,
        'cert_verified': True,   # ✅ ADDED
    }
 
@pytest.fixture
def pqc_scan():
    return {
        'hostname': 'pqc.pnb.co.in', 'cert_subject': 'CN=pqc.pnb.co.in',
        'cert_issuer': 'PQC Test CA', 'cert_not_before': '2024-01-01T00:00:00+00:00',
        'cert_not_after':  '2027-01-01T00:00:00+00:00', 'cert_days_remaining': 700,
        'cert_sig_algorithm': 'ML-DSA-65 (Dilithium3) [FIPS 204]',
        'cert_sig_oid': '2.16.840.1.101.3.4.3.18',
        'cert_key_size': 3072,   # ✅ UPDATED (realistic PQC size, no logic change)
        'cert_key_type': 'ML-DSA',
        'cert_sha1_fp': '11:22:33:44:55', 'cert_sha256_fp': '66:77:88:99',
        'cert_san': ['pqc.pnb.co.in'],
        'tls_version': 'TLSv1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384',
        'key_exchange': 'ECDHE', 'forward_secrecy': True, 'is_pqc_algorithm': True,
        'cert_verified': True,   # ✅ ADDED
    }
 
def test_cbom_has_all_sections(generator, mock_scan):
    cbom = generator.generate_cbom([mock_scan])
    assert 'certificates' in cbom
    assert 'keys'         in cbom
    assert 'algorithms'   in cbom
    assert 'protocols'    in cbom
    assert 'summary'      in cbom
    assert 'cbom_version' in cbom
    assert 'generated_at' in cbom
    assert 'tool_name'    in cbom
 
def test_cbom_cert_annexure_a_fields(generator, mock_scan):
    """Verify all 9 Cert-In Annexure-A certificate fields are present."""
    cbom = generator.generate_cbom([mock_scan])
    cert = cbom['certificates'][0]
    required = ['hostname','cert_subject','cert_issuer','cert_not_before','cert_not_after',
                'cert_days_remaining','sig_algorithm','sig_oid','cert_sha1_fingerprint']
    for field in required:
        assert field in cert, f'Missing Annexure-A field: {field}'
 
def test_cbom_key_security_bits_rsa2048(generator, mock_scan):
    cbom = generator.generate_cbom([mock_scan])
    key  = cbom['keys'][0]
    assert key['key_type']              == 'RSA'
    assert key['key_size_bits']         == 2048
    assert key['classical_security_bits'] == 112  # NIST SP800-57 Table 2
    assert key['quantum_resistance']    == 'NO'
 
def test_cbom_pqc_algorithm_detected(generator, pqc_scan):
    cbom = generator.generate_cbom([pqc_scan])
    alg  = cbom['algorithms'][0]
    assert alg['is_pqc']            == True
    assert alg['vulnerability_risk'] == 'NONE (PQC)'
    assert 'ML-DSA' in alg['algorithm_name'] or 'Dilithium' in alg['algorithm_name']
 
def test_cbom_algorithm_deduplication(generator, mock_scan):
    """Same algorithm across two hosts should only appear once in cbom['algorithms']."""
    scan2 = dict(mock_scan); scan2['hostname'] = 'api.pnb.co.in'
    cbom  = generator.generate_cbom([mock_scan, scan2])
    assert len(cbom['algorithms']) == 1  # deduplicated by OID
 
def test_cbom_summary_counts(generator, mock_scan, pqc_scan):
    cbom = generator.generate_cbom([mock_scan, pqc_scan])
    assert cbom['summary']['total_assets']  == 2
    assert cbom['summary']['pqc_count']     == 1
    assert cbom['summary']['total_certs']   == 2
 
def test_csv_export_not_empty(generator, mock_scan):
    cbom = generator.generate_cbom([mock_scan])
    csv  = generator.to_csv(cbom)
    assert '=== CERTIFICATES ===' in csv
    assert '=== PUBLIC KEYS ===' in csv
    assert '=== ALGORITHMS ===' in csv
    assert '=== PROTOCOLS ===' in csv
    assert 'test.pnb.co.in' in csv
 
def test_csv_export_certificate_fields(generator, mock_scan):
    cbom = generator.generate_cbom([mock_scan])
    csv  = generator.to_csv(cbom)
    for field in ['hostname','cert_subject','sig_algorithm','cert_sha1_fingerprint']:
        assert field in csv, f'Missing CSV column: {field}'
 
# ✅ NEW TEST — Protocol validation (no modification to existing code)
def test_cbom_protocol_section(generator, mock_scan):
    cbom = generator.generate_cbom([mock_scan])
    proto = cbom['protocols'][0]
 
    assert proto['protocol_version'] == 'TLSv1.3'
    assert proto['cipher_suite'] == 'TLS_AES_256_GCM_SHA384'
    assert proto['key_exchange'] == 'ECDHE'
 
# ✅ NEW TEST — Edge case (empty input)
def test_empty_input(generator):
    cbom = generator.generate_cbom([])
    assert cbom['summary']['total_assets'] == 0
    assert cbom['certificates'] == []
 
