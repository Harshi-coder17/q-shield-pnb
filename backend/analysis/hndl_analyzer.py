from datetime import datetime, timezone

# ── Constants ─────────────────────────────────────────────────────────────────

CRQC_ESTIMATED_YEAR = 2035  # Conservative estimate: CRQC capable of breaking RSA-2048

# Algorithms broken by Shor's algorithm on a CRQC
VULNERABLE_ALGORITHMS = ['RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'Diffie-Hellman']

# PQC algorithms that are NOT broken by Shor's algorithm
PQC_SAFE_MARKERS = [
    'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON',
    'Dilithium', 'Kyber', 'SPHINCS',
    'FIPS 203', 'FIPS 204', 'FIPS 205',
]

# Key exchange methods that provide forward secrecy (past traffic safe even if key later broken)
FORWARD_SECRECY_KE = ['ECDHE', 'DHE']

# Key exchange methods vulnerable to HNDL (no forward secrecy)
VULNERABLE_KE = ['RSA', 'ECDH', 'DH']

# Data sensitivity profiles — defines how long data must be kept confidential
SENSITIVITY_PROFILES = {
    'financial_transactions': {
        'retention_years': 10,
        'sensitivity': 'CRITICAL',
        'description': 'Payment records, transaction logs, inter-bank transfers',
        'regulatory_ref': 'RBI Master Direction on Digital Payment Security (2021)',
    },
    'customer_pii': {
        'retention_years': 7,
        'sensitivity': 'HIGH',
        'description': 'Customer identity, KYC data, account details',
        'regulatory_ref': 'IT Act 2000 / DPDP Act 2023',
    },
    'general_banking': {
        'retention_years': 5,
        'sensitivity': 'MEDIUM',
        'description': 'General banking communications, internal memos',
        'regulatory_ref': 'RBI Guidelines on IS Framework',
    },
    'public': {
        'retention_years': 1,
        'sensitivity': 'LOW',
        'description': 'Public-facing website content, marketing material',
        'regulatory_ref': 'N/A',
    },
}

# ── HNDL Analyzer ─────────────────────────────────────────────────────────────

class HNDLAnalyzer:
    

    def analyze(self, tls_data: dict, data_profile: str = 'financial_transactions') -> dict:
       
        current_year = datetime.now(timezone.utc).year
        years_to_crqc = CRQC_ESTIMATED_YEAR - current_year

        profile = SENSITIVITY_PROFILES.get(
            data_profile,
            SENSITIVITY_PROFILES['financial_transactions']
        )
        retention_years = profile['retention_years']

        sig_algorithm = tls_data.get('cert_sig_algorithm', '')
        key_exchange   = tls_data.get('key_exchange', '').upper()
        cipher_suite   = tls_data.get('cipher_suite', '')
        forward_secrecy = tls_data.get('forward_secrecy', False)

        # ── Algorithm Vulnerability ──────────────────────────────────────────
        # Check if cert signature algorithm is PQC-safe first
        is_pqc_safe = any(m.upper() in sig_algorithm.upper() for m in PQC_SAFE_MARKERS)

        # Check if cert signature algorithm is quantum-vulnerable
        algo_vulnerable = (
            not is_pqc_safe and
            any(v.upper() in sig_algorithm.upper() for v in VULNERABLE_ALGORITHMS)
        )

        # ── Key Exchange Vulnerability ───────────────────────────────────────
        # Forward secrecy (ECDHE/DHE) means past sessions are safe even if long-term
        # key is later broken. Static key exchange (RSA, ECDH) is vulnerable.
        has_forward_secrecy = (
            forward_secrecy or
            any(fs in key_exchange for fs in FORWARD_SECRECY_KE)
        )
        ke_vulnerable = (
            not has_forward_secrecy and
            any(v in key_exchange for v in VULNERABLE_KE)
        )

        # ── HNDL Exposure Window ─────────────────────────────────────────────
        # Data captured today needs to stay secret for `retention_years`.
        # If retention_years > years_to_crqc, the data will still be sensitive
        # when a CRQC becomes available — making it a HNDL target.
        data_outlives_quantum = retention_years > years_to_crqc

        # ── Risk Level Decision ──────────────────────────────────────────────
        risk_level, risk_score = self._compute_risk(
            algo_vulnerable, ke_vulnerable, data_outlives_quantum, profile['sensitivity']
        )

        # ── Threat Factors (for report detail) ──────────────────────────────
        threat_factors = self._collect_threat_factors(
            algo_vulnerable, ke_vulnerable, data_outlives_quantum,
            sig_algorithm, key_exchange, cipher_suite, has_forward_secrecy,
            retention_years, years_to_crqc
        )

        return {
            # Core risk output
            'hndl_risk':              risk_level,
            'hndl_risk_score':        risk_score,

            # Algorithm analysis
            'algorithm_breakable':    algo_vulnerable,
            'is_pqc_safe':            is_pqc_safe,
            'encryption_algorithm':   sig_algorithm,
            'key_exchange':           key_exchange,
            'has_forward_secrecy':    has_forward_secrecy,
            'ke_vulnerable':          ke_vulnerable,

            # Time window analysis
            'current_year':           current_year,
            'crqc_estimated_year':    CRQC_ESTIMATED_YEAR,
            'years_to_crqc':          years_to_crqc,
            'data_outlives_quantum_window': data_outlives_quantum,

            # Data profile
            'data_profile':           data_profile,
            'data_sensitivity':       profile['sensitivity'],
            'retention_years':        retention_years,
            'regulatory_ref':         profile['regulatory_ref'],

            # Human-readable output
            'threat_factors':         threat_factors,
            'explanation':            self._build_explanation(
                                          risk_level, algo_vulnerable, ke_vulnerable,
                                          data_outlives_quantum, retention_years,
                                          years_to_crqc, sig_algorithm, profile
                                      ),
            'recommendation':         self._get_recommendation(risk_level),
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _compute_risk(
        self,
        algo_vulnerable: bool,
        ke_vulnerable: bool,
        data_outlives_quantum: bool,
        sensitivity: str
    ) -> tuple:
        
        if algo_vulnerable and data_outlives_quantum:
            # Both conditions for full HNDL attack met
            score = 90 if ke_vulnerable else 75
            return 'HIGH', score

        elif algo_vulnerable and not data_outlives_quantum:
            # Algorithm broken but data won't be sensitive by then
            score = 60 if ke_vulnerable else 45
            return 'MEDIUM', score

        elif not algo_vulnerable and ke_vulnerable and data_outlives_quantum:
            # PQC cert but weak key exchange — partial exposure
            return 'MEDIUM', 40

        else:
            return 'LOW', 10

    def _collect_threat_factors(
        self,
        algo_vulnerable, ke_vulnerable, data_outlives_quantum,
        sig_algorithm, key_exchange, cipher_suite, has_forward_secrecy,
        retention_years, years_to_crqc
    ) -> list:
        """Build a list of specific threat factors found."""
        factors = []

        if algo_vulnerable:
            factors.append(
                f"Certificate uses {sig_algorithm} — broken by Shor's algorithm on a CRQC"
            )
        if ke_vulnerable:
            factors.append(
                f"Key exchange ({key_exchange}) lacks forward secrecy — "
                f"past sessions decryptable if long-term key is compromised"
            )
        if data_outlives_quantum:
            factors.append(
                f"Data retained for {retention_years} years exceeds "
                f"CRQC arrival window ({years_to_crqc} years) — HNDL window open"
            )
        if not has_forward_secrecy and key_exchange:
            factors.append(
                "No ephemeral key exchange detected — all recorded sessions at risk"
            )
        if not factors:
            factors.append("No significant HNDL threat factors detected")

        return factors

    def _build_explanation(
        self,
        risk, algo_vuln, ke_vuln, data_outlives,
        ret_years, yrs_to_crqc, sig, profile
    ) -> str:
        """Generate a human-readable risk explanation."""
        if risk == 'HIGH':
            return (
                f"HIGH HNDL EXPOSURE: {profile['description']} protected by {sig} "
                f"(quantum-vulnerable) is retained for {ret_years} years, but CRQCs "
                f"are estimated to emerge in ~{yrs_to_crqc} years. "
                f"Adversaries capturing this traffic today can decrypt it circa "
                f"{CRQC_ESTIMATED_YEAR}. Immediate PQC migration required."
            )
        elif risk == 'MEDIUM':
            if algo_vuln:
                return (
                    f"MEDIUM HNDL EXPOSURE: {sig} is quantum-vulnerable. "
                    f"While data retention ({ret_years} yr) may not fully exceed the "
                    f"CRQC window ({yrs_to_crqc} yr), begin PQC migration within 18 months."
                )
            else:
                return (
                    f"MEDIUM HNDL EXPOSURE: Certificate algorithm appears PQC-safe, "
                    f"but key exchange lacks forward secrecy. Stored session keys "
                    f"could be targeted. Plan migration to ECDHE + PQC hybrid."
                )
        else:
            return (
                f"LOW HNDL EXPOSURE: Encryption appears adequate for the expected "
                f"data lifetime of {ret_years} year(s). "
                f"Continue monitoring NIST FIPS 203/204/205 updates and schedule "
                f"a PQC readiness review in the next annual security assessment."
            )

    def _get_recommendation(self, risk_level: str) -> str:
        """Return a concrete remediation recommendation."""
        return {
            'HIGH': (
                "URGENT: Migrate to hybrid PQC key exchange (ML-KEM-768 + ECDHE) "
                "IMMEDIATELY. Replace certificates with ML-DSA signatures [FIPS 204]. "
                "Audit all stored encrypted archives for retroactive exposure. "
                "Notify CISO and initiate incident response review per Cert-In guidelines."
            ),
            'MEDIUM': (
                "Plan PQC migration within 18 months. Prioritize assets handling "
                "long-lived sensitive data. Enable ECDHE for forward secrecy as an "
                "interim measure. Implement a crypto-agility framework to allow "
                "algorithm updates without service disruption."
            ),
            'LOW': (
                "Monitor NIST PQC standards (FIPS 203/204/205). "
                "Schedule a PQC migration feasibility review in the next annual "
                "security assessment. No immediate action required."
            ),
        }.get(risk_level, '')


# ── Standalone test ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    analyzer = HNDLAnalyzer()

    print("=" * 60)
    print("TEST 1: RSA cert, no forward secrecy, financial data")
    r = analyzer.analyze(
        tls_data={
            'cert_sig_algorithm': 'RSA-SHA256',
            'key_exchange': 'RSA',
            'cipher_suite': 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'forward_secrecy': False,
        },
        data_profile='financial_transactions'
    )
    print(f"  Risk: {r['hndl_risk']} (score {r['hndl_risk_score']})")
    print(f"  Algo breakable: {r['algorithm_breakable']}")
    print(f"  Explanation: {r['explanation'][:100]}...")

    print("\nTEST 2: PQC cert (ML-DSA), ECDHE, public data")
    r2 = analyzer.analyze(
        tls_data={
            'cert_sig_algorithm': 'ML-DSA-65 [FIPS 204]',
            'key_exchange': 'ECDHE',
            'cipher_suite': 'TLS_AES_256_GCM_SHA384',
            'forward_secrecy': True,
        },
        data_profile='public'
    )
    print(f"  Risk: {r2['hndl_risk']} (score {r2['hndl_risk_score']})")
    print(f"  Algo breakable: {r2['algorithm_breakable']}")

    print("\nTEST 3: ECDSA cert, ECDHE (forward secrecy), customer PII")
    r3 = analyzer.analyze(
        tls_data={
            'cert_sig_algorithm': 'ECDSA-SHA256',
            'key_exchange': 'ECDHE',
            'cipher_suite': 'TLS_AES_128_GCM_SHA256',
            'forward_secrecy': True,
        },
        data_profile='customer_pii'
    )
    print(f"  Risk: {r3['hndl_risk']} (score {r3['hndl_risk_score']})")
    print(f"  Data outlives quantum: {r3['data_outlives_quantum_window']}")
    print(f"  Has forward secrecy: {r3['has_forward_secrecy']}")
    print(f"  Explanation: {r3['explanation'][:100]}...")
