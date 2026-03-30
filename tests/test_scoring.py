# tests/test_scoring.py
# Q-Shield — Unit Tests for Scoring Engine & HNDL Analyzer
# Requires: pytest.ini at project root with DJANGO_SETTINGS_MODULE = qshield.settings
 
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
 
from analysis.scoring_engine import QuantumScoringEngine
from analysis.hndl_analyzer  import HNDLAnalyzer
 
@pytest.fixture
def scorer(): return QuantumScoringEngine()
 
@pytest.fixture
def hndl(): return HNDLAnalyzer()
 
# ── Scoring Engine Tests ──
def test_tls13_aead_ecdhe_scores_high(scorer):
    data = {'tls_version':'TLSv1.3','cipher_suite':'TLS_AES_256_GCM_SHA384',
            'key_exchange':'ECDHE','forward_secrecy':True,'cert_key_size':4096,
            'cert_sig_algorithm':'ECDSA-SHA384','cert_days_remaining':365}
    r = scorer.score(data, cert_reuse=False)
    assert r['score'] >= 60, f'Expected >=60, got {r["score"]}'
    assert r['dimension_scores']['tls_version']   == 25
    assert r['dimension_scores']['cipher_suite']  == 20
    assert r['dimension_scores']['key_exchange']  == 20
 
def test_expired_cert_scores_zero_validity(scorer):
    data = {'tls_version':'TLSv1.3','cipher_suite':'TLS_AES_256_GCM_SHA384',
            'key_exchange':'ECDHE','forward_secrecy':True,'cert_key_size':2048,
            'cert_sig_algorithm':'RSA-SHA256','cert_days_remaining':-5}
    r = scorer.score(data)
    assert r['dimension_scores']['cert_validity'] == 0
 
def test_tls10_weak_gets_critical_label(scorer):
    data = {'tls_version':'TLSv1.0','cipher_suite':'TLS_RSA_WITH_DES_CBC_SHA',
            'key_exchange':'RSA','forward_secrecy':False,'cert_key_size':1024,
            'cert_sig_algorithm':'RSA-SHA1','cert_days_remaining':-30}
    r = scorer.score(data, cert_reuse=True)
    assert r['score'] < 30
    assert r['label']['text'] == 'Critical'
    assert len(r['vulnerabilities']) >= 3
 
def test_pqc_algorithm_detected(scorer):
    data = {'tls_version':'TLSv1.3','cipher_suite':'TLS_AES_256_GCM_SHA384',
            'key_exchange':'ECDHE','forward_secrecy':True,'cert_key_size':4096,
            'cert_sig_algorithm':'ML-DSA-65 (Dilithium3) [FIPS 204]','cert_days_remaining':730}
    r = scorer.score(data)
    assert r['is_pqc'] == True
    assert r['dimension_scores']['cert_algorithm'] == 15
    assert r['score'] >= 90
    assert r['label']['text'] == 'Fully Quantum Safe'
 
def test_cert_reuse_reduces_score(scorer):
    data = {'tls_version':'TLSv1.3','cipher_suite':'TLS_AES_256_GCM_SHA384',
            'key_exchange':'ECDHE','forward_secrecy':True,'cert_key_size':4096,
            'cert_sig_algorithm':'ECDSA-SHA384','cert_days_remaining':365}
    no_reuse   = scorer.score(data, cert_reuse=False)
    with_reuse = scorer.score(data, cert_reuse=True)
    assert no_reuse['score'] > with_reuse['score']
    assert with_reuse['dimension_scores']['cert_reuse'] == 0
 
def test_label_boundaries(scorer):
    assert scorer._assign_label(95)['text'] == 'Fully Quantum Safe'
    assert scorer._assign_label(90)['text'] == 'Fully Quantum Safe'
    assert scorer._assign_label(60)['text'] == 'PQC Ready'
    assert scorer._assign_label(75)['text'] == 'PQC Ready'
    assert scorer._assign_label(30)['text'] == 'Quantum Vulnerable'
    assert scorer._assign_label(50)['text'] == 'Quantum Vulnerable'
    assert scorer._assign_label(0)['text']  == 'Critical'
    assert scorer._assign_label(29)['text'] == 'Critical'
 
def test_hndl_high_risk_for_rsa_and_long_retention(hndl):
    data = {'cert_sig_algorithm':'RSA-SHA256','key_exchange':'RSA',
            'cipher_suite':'TLS_RSA_WITH_AES_256_CBC_SHA','forward_secrecy':False}
    r = hndl.analyze(data, data_profile='financial_transactions')
    assert r['hndl_risk'] == 'HIGH'
    assert r['algorithm_breakable'] == True
 
def test_hndl_low_risk_for_pqc(hndl):
    data = {'cert_sig_algorithm':'ML-DSA-65 [FIPS 204]','key_exchange':'ECDHE',
            'cipher_suite':'TLS_AES_256_GCM_SHA384','forward_secrecy':True}
    r = hndl.analyze(data, data_profile='public')
    assert r['hndl_risk'] in ('LOW', 'MEDIUM')
    assert r['algorithm_breakable'] == False
 
# Run: python -m pytest tests/test_scoring.py -v
