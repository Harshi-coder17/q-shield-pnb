from datetime import datetime, timezone
 
CRQC_ESTIMATED_YEAR = 2035  # Conservative estimate for CRQC breaking RSA-2048
 
VULNERABLE_FOR_HNDL = ['RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'Diffie-Hellman']
 
SENSITIVITY_PROFILES = {
    'financial_transactions': {'retention_years': 10, 'sensitivity': 'CRITICAL', 'description': 'Payment records, transaction logs'},
    'customer_pii':           {'retention_years':  7, 'sensitivity': 'HIGH',     'description': 'Customer identity, account details'},
    'general_banking':        {'retention_years':  5, 'sensitivity': 'MEDIUM',   'description': 'General banking communications'},
    'public':                 {'retention_years':  1, 'sensitivity': 'LOW',      'description': 'Public-facing website content'},
}
 
class HNDLAnalyzer:
    """
    Assesses Harvest-Now-Decrypt-Later (HNDL) risk.
    HNDL attack scenario:
      1. Adversary records encrypted traffic TODAY
      2. Stores it until quantum computers are available (~2035)
      3. Uses CRQC to break RSA/ECDSA and decrypt stored data
    Risk is HIGH if: algorithm is quantum-vulnerable AND
                     data lifetime > years until CRQC is available
    """
 
    def analyze(self, tls_data: dict, data_profile: str = 'financial_transactions') -> dict:
        current_year  = datetime.now(timezone.utc).year
        years_to_crqc = CRQC_ESTIMATED_YEAR - current_year
        profile       = SENSITIVITY_PROFILES.get(data_profile, SENSITIVITY_PROFILES['financial_transactions'])
        retention_years = profile['retention_years']
 
        sig          = tls_data.get('cert_sig_algorithm', '')
        key_exchange = tls_data.get('key_exchange', '').upper()
        algo_vulnerable = any(v.upper() in sig.upper() for v in VULNERABLE_FOR_HNDL)
        ke_vulnerable   = any(v in key_exchange for v in ['RSA', 'DH'] if 'ECDHE' not in key_exchange)
        data_outlives_quantum = retention_years > years_to_crqc
 
        if   algo_vulnerable and data_outlives_quantum:  risk_level, risk_score = 'HIGH',   90
        elif algo_vulnerable and not data_outlives_quantum: risk_level, risk_score = 'MEDIUM', 55
        elif not algo_vulnerable and data_outlives_quantum: risk_level, risk_score = 'MEDIUM', 40
        else:                                             risk_level, risk_score = 'LOW',    10
 
        return {
            'hndl_risk': risk_level, 'hndl_risk_score': risk_score,
            'data_profile': data_profile, 'data_sensitivity': profile['sensitivity'],
            'retention_years': retention_years, 'years_to_crqc': years_to_crqc,
            'crqc_estimated_year': CRQC_ESTIMATED_YEAR,
            'algorithm_breakable': algo_vulnerable,
            'data_outlives_quantum_window': data_outlives_quantum,
            'encryption_algorithm': sig,
            'explanation': self._build_explanation(risk_level, algo_vulnerable, data_outlives_quantum,
                                                    retention_years, years_to_crqc, sig, profile),
            'recommendation': self._get_recommendation(risk_level)
        }
 
    def _build_explanation(self, risk, algo_vuln, data_outlives, ret_years, yrs_to_crqc, sig, profile) -> str:
        if risk == 'HIGH':
            return (f'HIGH HNDL EXPOSURE: {profile["description"]} protected by {sig} (quantum-vulnerable) '
                    f'is retained for {ret_years} years, but CRQCs estimated to emerge in {yrs_to_crqc} years. '
                    f'Adversaries capturing this traffic today can decrypt it circa {CRQC_ESTIMATED_YEAR}.')
        elif risk == 'MEDIUM':
            return (f'MEDIUM HNDL EXPOSURE: Algorithm is quantum-vulnerable or data retention exceeds quantum safety window. '
                    f'Begin PQC migration planning within 12-18 months.')
        return ('LOW HNDL EXPOSURE: Encryption appears adequate for expected data lifetime. '
                'Continue monitoring NIST PQC standardization updates.')
 
    def _get_recommendation(self, risk_level: str) -> str:
        return {
            'HIGH':   'URGENT: Migrate to hybrid PQC key exchange (ML-KEM-768 + ECDHE) IMMEDIATELY. Replace certificates with ML-DSA signatures [FIPS 204]. Assess all stored encrypted data for retroactive exposure.',
            'MEDIUM': 'Plan PQC migration within 18 months. Prioritize services handling long-lived sensitive data. Implement crypto-agility framework.',
            'LOW':    'Monitor NIST PQC standards (FIPS 203/204/205). Schedule PQC migration review in next annual security assessment.'
        }.get(risk_level, '')
