# backend/scanner/tls_scanner.py
# Q-Shield — TLS Scanner Engine
# Owner: Member 1 (Team Lead / TLS Scanner Engineer)
# SRS References: FR-02 (TLS Handshake), FR-03 (Certificate Parsing)

import ssl
import socket
import hashlib
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import logging
import certifi

logger = logging.getLogger(__name__)

# ── OID → Algorithm Name Mapping (NIST PQC + Classical) ──
OID_ALGORITHM_MAP = {
    # Classical signature algorithms
    '1.2.840.113549.1.1.5': 'RSA-SHA1',
    '1.2.840.113549.1.1.11': 'RSA-SHA256',
    '1.2.840.113549.1.1.12': 'RSA-SHA384',
    '1.2.840.113549.1.1.13': 'RSA-SHA512',
    '1.2.840.10045.4.3.1': 'ECDSA-SHA224',
    '1.2.840.10045.4.3.2': 'ECDSA-SHA256',
    '1.2.840.10045.4.3.3': 'ECDSA-SHA384',
    '1.2.840.10045.4.3.4': 'ECDSA-SHA512',
    '1.2.840.10040.4.3': 'DSA-SHA1',

    # NIST PQC algorithms (FIPS 203/204/205)
    '2.16.840.1.101.3.4.3.17': 'ML-DSA-44 (Dilithium2) [FIPS 204]',
    '2.16.840.1.101.3.4.3.18': 'ML-DSA-65 (Dilithium3) [FIPS 204]',
    '2.16.840.1.101.3.4.3.19': 'ML-DSA-87 (Dilithium5) [FIPS 204]',
    '2.16.840.1.101.3.4.3.20': 'SLH-DSA-SHA2-128s (SPHINCS+) [FIPS 205]',
    '2.16.840.1.101.3.4.4.1': 'ML-KEM-512 (Kyber512) [FIPS 203]',
    '2.16.840.1.101.3.4.4.2': 'ML-KEM-768 (Kyber768) [FIPS 203]',
    '2.16.840.1.101.3.4.4.3': 'ML-KEM-1024 (Kyber1024) [FIPS 203]',
    '1.3.9999.3.1': 'FALCON-512 [NIST Round 4]',
    '1.3.9999.3.4': 'FALCON-1024 [NIST Round 4]',
}

WEAK_CIPHER_PATTERNS = [
    'DES', '3DES', 'RC4', 'RC2', 'NULL', 'EXPORT',
    'anon', 'MD5', 'SHA1', 'CBC'
]

PQC_ALGORITHM_NAMES = [
    'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON',
    'Dilithium', 'Kyber', 'SPHINCS'
]


class TLSScanner:
    """
    Passive TLS scanner — makes only outbound connections.
    Never modifies target systems. Read-only inspection only.
    Compliant with SRS Section 8 (passive / non-intrusive requirement).
    """

    def __init__(self, hostname: str, port: int = 443, timeout: int = 20):
        self.hostname = hostname.strip().lower()
        self.port = port
        self.timeout = timeout

    def scan(self) -> dict:
        try:
            ctx = ssl.create_default_context(cafile=certifi.where())
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3

            with socket.create_connection(
                (self.hostname, self.port), timeout=self.timeout
            ) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=self.hostname) as tls_sock:
                    tls_version = tls_sock.version()
                    cipher_info = tls_sock.cipher()
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    peer_cert_dict = tls_sock.getpeercert()

                    cert = x509.load_der_x509_certificate(
                        der_cert, default_backend()
                    )

                    return self._build_result(
                        tls_version,
                        cipher_info,
                        cert,
                        der_cert,
                        peer_cert_dict
                    )

        except ssl.SSLCertVerificationError:
            return self._scan_with_verification_off()

        except ssl.SSLError as e:
            return {
                'error': f'SSL handshake failed: {str(e)}',
                'hostname': self.hostname
            }

        except socket.timeout:
            return {
                'error': f'Connection timed out after {self.timeout}s',
                'hostname': self.hostname
            }

        except ConnectionRefusedError:
            return {
                'error': 'Port 443 refused — target not accepting TLS',
                'hostname': self.hostname
            }

        except OSError as e:
            return {
                'error': f'Network error: {str(e)}',
                'hostname': self.hostname
            }

    def _scan_with_verification_off(self) -> dict:
        """Fallback: scan without cert verification to still get TLS data."""
        try:
            ctx = ssl.create_default_context(cafile=certifi.where())
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            with socket.create_connection(
                (self.hostname, self.port), timeout=self.timeout
            ) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=self.hostname) as tls_sock:
                    tls_version = tls_sock.version()
                    cipher_info = tls_sock.cipher()
                    der_cert = tls_sock.getpeercert(binary_form=True)

                    cert = x509.load_der_x509_certificate(
                        der_cert, default_backend()
                    )

                    result = self._build_result(
                        tls_version,
                        cipher_info,
                        cert,
                        der_cert,
                        {}
                    )

                    result['cert_verified'] = False
                    result['cert_verification_warning'] = (
                        'Certificate could not be verified against trusted CAs. '
                        'Self-signed or chain incomplete.'
                    )

                    return result

        except Exception as e:
            return {'error': str(e), 'hostname': self.hostname}

    def _build_result(self, tls_version, cipher_info, cert, der_cert, peer_dict) -> dict:
        sha1_fp = self._format_fingerprint(hashlib.sha1(der_cert).hexdigest())
        sha256_fp = self._format_fingerprint(hashlib.sha256(der_cert).hexdigest())

        subject_cn = self._get_cn(cert.subject)
        issuer_cn = self._get_cn(cert.issuer)

        subject_dn = cert.subject.rfc4514_string()
        issuer_dn = cert.issuer.rfc4514_string()

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_name = OID_ALGORITHM_MAP.get(sig_oid, f'Unknown ({sig_oid})')

        pub_key = cert.public_key()
        key_size = self._get_key_size(pub_key)
        key_type = self._get_key_type(pub_key)

        cipher_name = cipher_info[0] if cipher_info else 'UNKNOWN'
        cipher_bits = cipher_info[2] if cipher_info else 0

        if tls_version == 'TLSv1.3':
            forward_secrecy = True
        else:
            forward_secrecy = 'ECDHE' in cipher_name or 'DHE' in cipher_name
        is_aead = (
            'GCM' in cipher_name or
            'CCM' in cipher_name or
            'CHACHA20' in cipher_name
        )

        is_weak = any(w in cipher_name.upper() for w in WEAK_CIPHER_PATTERNS)

        if tls_version == 'TLSv1.3':
            key_exchange = 'ECDHE'
        elif 'ECDHE' in cipher_name:
            key_exchange = 'ECDHE'
        elif 'DHE' in cipher_name:
            key_exchange = 'DHE'
        elif 'ECDH' in cipher_name:
            key_exchange = 'ECDH'
        else:
            key_exchange = 'RSA'

        is_pqc = any(p.upper() in sig_name.upper() for p in PQC_ALGORITHM_NAMES)

        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        return {
            'hostname': self.hostname,
            'port': self.port,
            'tls_version': tls_version,
            'cipher_suite': cipher_name,
            'cipher_bits': cipher_bits,
            'key_exchange': key_exchange,
            'forward_secrecy': forward_secrecy,
            'is_aead_cipher': is_aead,
            'is_weak_cipher': is_weak,
            'cert_subject': subject_cn,
            'cert_subject_dn': subject_dn,
            'cert_issuer': issuer_cn,
            'cert_issuer_dn': issuer_dn,
            'cert_not_before': not_before.isoformat(),
            'cert_not_after': not_after.isoformat(),
            'cert_days_remaining': days_remaining,
            'cert_sig_algorithm': sig_name,
            'cert_sig_oid': sig_oid,
            'cert_key_size': key_size,
            'cert_key_type': key_type,
            'cert_sha1_fp': sha1_fp,
            'cert_sha256_fp': sha256_fp,
            'cert_format': 'X.509',
            'cert_san': san_list,
            'cert_verified': True,
            'is_pqc_algorithm': is_pqc,
            'scanned_at': now.isoformat(),
            'error': None,
        }

    def _format_fingerprint(self, hex_str: str) -> str:
        upper = hex_str.upper()
        return ':'.join(upper[i:i+2] for i in range(0, len(upper), 2))

    def _get_cn(self, name_obj) -> str:
        try:
            attrs = name_obj.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else str(name_obj)
        except Exception:
            return str(name_obj)

    def _get_key_size(self, pub_key) -> int:
        try:
            return pub_key.key_size
        except AttributeError:
            try:
                return pub_key.public_numbers().x.bit_length()
            except Exception:
                return 0

    def _get_key_type(self, pub_key) -> str:
        t = type(pub_key).__name__
        if 'RSA' in t:
            return 'RSA'
        if 'EC' in t:
            return 'ECDSA'
        if 'DSA' in t:
            return 'DSA'
        if 'Ed25519' in t:
            return 'Ed25519'
        return 'Unknown'


# ── Quick test — run directly to verify scanner works ──
if __name__ == '__main__':
    import json

    scanner = TLSScanner('google.com')
    result = scanner.scan()

    print(json.dumps(result, indent=2, default=str))