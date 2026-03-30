import sys, os, json
# ✅ FIXED PATH (critical)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'qshield.settings')

import django
django.setup()  # MUST call before importing any Django models

# ── Django model imports — this is how Django works, NOT Flask ──
from qshield.models import ScanResult, Asset
from scanner.tls_scanner import TLSScanner
from analysis.scoring_engine import QuantumScoringEngine
from analysis.hndl_analyzer import HNDLAnalyzer
from reporting.cbom_generator import CBOMGenerator

SCORER = QuantumScoringEngine()
HNDL_A = HNDLAnalyzer()

# ── Demo Targets — PNB and partner banking domains ──
DEMO_TARGETS = [
    {'hostname': 'pnb.co.in',            'tls_version': 'TLSv1.2', 'cipher': 'ECDHE-RSA-AES256-GCM-SHA384',
     'ke': 'ECDHE', 'ks': 2048, 'sig': 'RSA-SHA256', 'oid': '1.2.840.113549.1.1.11',
     'issuer': 'DigiCert TLS RSA SHA256 2020 CA1', 'days': 145, 'fs': True, 'aead': True, 'weak': False},

    {'hostname': 'netbanking.pnb.co.in', 'tls_version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384',
     'ke': 'ECDHE', 'ks': 2048, 'sig': 'RSA-SHA256', 'oid': '1.2.840.113549.1.1.11',
     'issuer': 'DigiCert TLS RSA SHA256 2020 CA1', 'days': 98,  'fs': True, 'aead': True, 'weak': False},

    {'hostname': 'api.pnb.co.in',        'tls_version': 'TLSv1.2', 'cipher': 'ECDHE-RSA-AES128-CBC-SHA256',
     'ke': 'ECDHE', 'ks': 2048, 'sig': 'RSA-SHA1',   'oid': '1.2.840.113549.1.1.5',
     'issuer': 'GlobalSign Organization Validation CA', 'days': 22, 'fs': True, 'aead': False, 'weak': False},

    {'hostname': 'portal.pnb.co.in',     'tls_version': 'TLSv1.2', 'cipher': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
     'ke': 'RSA',   'ks': 1024, 'sig': 'RSA-SHA1',   'oid': '1.2.840.113549.1.1.5',
     'issuer': 'VeriSign Class 3', 'days': 312, 'fs': False, 'aead': False, 'weak': True},

    {'hostname': 'sbi.co.in',            'tls_version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384',
     'ke': 'ECDHE', 'ks': 4096, 'sig': 'ECDSA-SHA384','oid': '1.2.840.10045.4.3.3',
     'issuer': 'Entrust CA', 'days': 210, 'fs': True, 'aead': True, 'weak': False},

    {'hostname': 'hdfcbank.com',         'tls_version': 'TLSv1.3', 'cipher': 'TLS_CHACHA20_POLY1305_SHA256',
     'ke': 'ECDHE', 'ks': 4096, 'sig': 'ECDSA-SHA384','oid': '1.2.840.10045.4.3.3',
     'issuer': 'DigiCert SHA2 EV Server CA', 'days': 88, 'fs': True, 'aead': True, 'weak': False},

    {'hostname': 'icicibank.com',        'tls_version': 'TLSv1.2', 'cipher': 'ECDHE-RSA-AES256-GCM-SHA384',
     'ke': 'ECDHE', 'ks': 2048, 'sig': 'RSA-SHA256', 'oid': '1.2.840.113549.1.1.11',
     'issuer': 'DigiCert TLS RSA SHA256 2020 CA1', 'days': 55, 'fs': True, 'aead': True, 'weak': False},

    {'hostname': 'rbi.org.in',           'tls_version': 'TLSv1.2', 'cipher': 'ECDHE-RSA-AES256-CBC-SHA384',
     'ke': 'ECDHE', 'ks': 2048, 'sig': 'RSA-SHA256', 'oid': '1.2.840.113549.1.1.11',
     'issuer': 'GlobalSign RSA OV SSL CA 2018', 'days': 178, 'fs': True, 'aead': False, 'weak': False},

    # ADDED PQC ENTRY (critical for CBOM correctness)
    {'hostname': 'quantum.pnb.co.in',    'tls_version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384',
     'ke': 'ECDHE', 'ks': 3072, 'sig': 'ML-DSA-65 (Dilithium3) [FIPS 204]',
     'oid': '2.16.840.1.101.3.4.3.18',
     'issuer': 'NIST PQC CA', 'days': 365, 'fs': True, 'aead': True, 'weak': False},
]

def make_fp(hostname: str, suffix: str = '') -> str:
    import hashlib
    h = hashlib.sha1((hostname + suffix).encode()).hexdigest().upper()
    return ':'.join(h[i:i+2] for i in range(0, 40, 2))

def seed():
    print('Q-Shield Demo Seeder — Django ORM version')
    print('Clearing existing demo data...')

    # Django ORM delete — NOT db.session.delete()
    ScanResult.objects.all().delete()
    Asset.objects.all().delete()
    print('Cleared.')

    cbom_gen = CBOMGenerator()
    created  = 0

    for t in DEMO_TARGETS:
        hostname = t['hostname']
        print(f'  Seeding: {hostname}')

        # Build synthetic TLS data dict (mirrors what TLSScanner returns)
        tls_data = {
            'hostname': hostname, 'port': 443,
            'tls_version': t['tls_version'], 'cipher_suite': t['cipher'],

            'cipher_bits': 128 if '128' in t['cipher'] else (112 if '3DES' in t['cipher'] else 256),

            'key_exchange': t['ke'],
            'forward_secrecy': t['fs'], 'is_aead_cipher': t['aead'],
            'is_weak_cipher': t['weak'],
            'cert_subject': f'CN={hostname}', 'cert_issuer': t['issuer'],
            'cert_not_before': '2024-01-15T00:00:00+00:00',
            'cert_not_after':  '2026-01-15T00:00:00+00:00',
            'cert_days_remaining': t['days'],
            'cert_sig_algorithm': t['sig'],
            'cert_sig_oid': t['oid'],
            'cert_key_size': t['ks'],
            'cert_key_type': 'ECDSA' if 'ECDSA' in t['sig'] else 'RSA',
            'cert_sha1_fp':   make_fp(hostname),
            'cert_sha256_fp': make_fp(hostname, '256'),
            'cert_san': [hostname, f'www.{hostname}'],
            'cert_verified': True, 'is_pqc_algorithm': 'ML-DSA' in t['sig'],
        }

        # Score using the scoring engine
        cert_reuse    = ScanResult.objects.filter(
            cert_sha1_fp=tls_data['cert_sha1_fp']
        ).exclude(hostname=hostname).exists()

        score_result  = SCORER.score(tls_data, cert_reuse)
        hndl          = HNDL_A.analyze(tls_data)
        cbom          = cbom_gen.generate_cbom([tls_data])

        # ── Django ORM create — NOT db.session.add() / db.session.commit() ──
        ScanResult.objects.create(
            hostname=hostname,
            tls_version=tls_data['tls_version'],
            cipher_suite=tls_data['cipher_suite'],
            cipher_bits=tls_data['cipher_bits'],
            key_exchange=tls_data['key_exchange'],
            forward_secrecy=tls_data['forward_secrecy'],
            is_aead_cipher=tls_data['is_aead_cipher'],
            is_weak_cipher=tls_data['is_weak_cipher'],
            cert_subject=tls_data['cert_subject'],
            cert_issuer=tls_data['cert_issuer'],
            cert_not_before=tls_data['cert_not_before'],
            cert_not_after=tls_data['cert_not_after'],
            cert_days_remaining=tls_data['cert_days_remaining'],
            cert_sig_algorithm=tls_data['cert_sig_algorithm'],
            cert_sig_oid=tls_data['cert_sig_oid'],
            cert_key_size=tls_data['cert_key_size'],
            cert_key_type=tls_data['cert_key_type'],
            cert_sha1_fp=tls_data['cert_sha1_fp'],
            cert_sha256_fp=tls_data['cert_sha256_fp'],
            cert_san=json.dumps(tls_data['cert_san']),
            cert_verified=tls_data['cert_verified'],
            quantum_score=score_result['score'],
            label=score_result['label']['text'],
            is_pqc_algorithm=score_result.get('is_pqc', False),
            dimension_scores=json.dumps(score_result['dimension_scores']),
            vulnerabilities=json.dumps(score_result['vulnerabilities']),
            recommendations=json.dumps(score_result['recommendations']),
            hndl_risk=hndl['hndl_risk'],
            hndl_explanation=hndl.get('explanation', ''),
            cbom_json=json.dumps(cbom),
            scanned_by='DEMO_SEED'
        )

        # Create corresponding Asset record
        Asset.objects.get_or_create(
            hostname=hostname,
            defaults={'asset_type': 'Web App', 'owner': 'PNB',
                      'port_443_open': True, 'source': 'demo-seed'}
        )

        created += 1

    print(f'Seeded {created} scan results successfully.')
    print('Run: cd backend && python manage.py runserver 0.0.0.0:8000')
    print('Then open: http://localhost:3000')

if __name__ == '__main__':
    seed()