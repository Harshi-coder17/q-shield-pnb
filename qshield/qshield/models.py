# backend/qshield/models.py
# Q-Shield — Django ORM Models
# Owner: Member 2 (Django Backend & API Infrastructure Engineer)
# SRS References: All FRs requiring data storage
 
from django.db import models
from django.contrib.auth.models import User
import json
 
class UserProfile(models.Model):
    """Extends Django User with RBAC role. SRS Section 8."""
    ROLE_CHOICES = [
        ('admin',   'Admin'),
        ('checker', 'Checker'),
        ('auditor', 'Auditor'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='auditor')
    def __str__(self): return f'{self.user.username} ({self.role})'
 
class Asset(models.Model):
    """Discovered assets inventory. SRS FR-15, FR-16."""
    hostname      = models.CharField(max_length=255, db_index=True)
    asset_type    = models.CharField(max_length=50, default='Web App')
    ipv4          = models.GenericIPAddressField(protocol='IPv4', blank=True, null=True)
    ipv6          = models.GenericIPAddressField(protocol='IPv6', blank=True, null=True)
    owner         = models.CharField(max_length=100, default='PNB')
    source        = models.CharField(max_length=50, blank=True)
    port_443_open = models.BooleanField(null=True)
    notes         = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_scanned  = models.DateTimeField(null=True, blank=True)
    def __str__(self): return self.hostname
    class Meta: ordering = ['-discovered_at']
class ScanResult(models.Model):
    """Complete scan result. SRS FR-02, FR-03, FR-06, FR-07, FR-08."""
    # ── Identity ──
    hostname            = models.CharField(max_length=255, db_index=True)
    # ── TLS Data ──
    tls_version         = models.CharField(max_length=20, blank=True)
    cipher_suite        = models.CharField(max_length=200, blank=True)
    cipher_bits         = models.IntegerField(null=True, blank=True)
    key_exchange        = models.CharField(max_length=100, blank=True)
    forward_secrecy     = models.BooleanField(null=True)
    is_aead_cipher      = models.BooleanField(null=True)
    is_weak_cipher      = models.BooleanField(null=True)
    # ── Certificate Data ──
    cert_subject        = models.CharField(max_length=500, blank=True)
    cert_subject_dn     = models.TextField(blank=True)
    cert_issuer         = models.CharField(max_length=500, blank=True)
    cert_issuer_dn      = models.TextField(blank=True)
    cert_not_before     = models.CharField(max_length=50, blank=True)
    cert_not_after      = models.CharField(max_length=50, blank=True)
    cert_days_remaining = models.IntegerField(null=True, blank=True)
    cert_sig_algorithm  = models.CharField(max_length=200, blank=True)
    cert_sig_oid        = models.CharField(max_length=100, blank=True)
    cert_key_size       = models.IntegerField(null=True, blank=True)
    cert_key_type       = models.CharField(max_length=50, blank=True)
    cert_sha1_fp        = models.CharField(max_length=200, blank=True)
    cert_sha256_fp      = models.CharField(max_length=200, blank=True)
    cert_san            = models.TextField(blank=True)  # JSON list
    cert_verified       = models.BooleanField(default=True)
    # ── PQC Analysis (populated by Member 3) ──
    quantum_score       = models.FloatField(null=True, blank=True)
    label               = models.CharField(max_length=50, blank=True)
    is_pqc_algorithm    = models.BooleanField(default=False)
    dimension_scores    = models.TextField(blank=True)  # JSON
    vulnerabilities     = models.TextField(blank=True)  # JSON
    recommendations     = models.TextField(blank=True)  # JSON
    # ── HNDL Risk (populated by Member 3) ──
    hndl_risk           = models.CharField(max_length=20, blank=True)
    hndl_explanation    = models.TextField(blank=True)
    # ── CBOM (populated by Member 4) ──
    cbom_json           = models.TextField(blank=True)  # JSON
    # ── Metadata ──
    scanned_at          = models.DateTimeField(auto_now_add=True, db_index=True)
    scanned_by          = models.CharField(max_length=100, default='system')
 
    def to_dict(self):
        return {
            'id': self.id, 'hostname': self.hostname,
            'tls_version': self.tls_version, 'cipher_suite': self.cipher_suite,
            'key_exchange': self.key_exchange, 'forward_secrecy': self.forward_secrecy,
            'cert_subject': self.cert_subject, 'cert_issuer': self.cert_issuer,
            'cert_not_before': self.cert_not_before, 'cert_not_after': self.cert_not_after,
            'cert_days_remaining': self.cert_days_remaining,
            'cert_sig_algorithm': self.cert_sig_algorithm, 'cert_sig_oid': self.cert_sig_oid,
            'cert_key_size': self.cert_key_size, 'cert_sha1_fp': self.cert_sha1_fp,
            'cert_verified': self.cert_verified, 'quantum_score': self.quantum_score,
            'label': self.label, 'is_pqc_algorithm': self.is_pqc_algorithm,
            'dimension_scores': json.loads(self.dimension_scores or '{}'),
            'vulnerabilities':  json.loads(self.vulnerabilities  or '[]'),
            'recommendations':  json.loads(self.recommendations  or '[]'),
            'hndl_risk': self.hndl_risk, 'hndl_explanation': self.hndl_explanation,
            'scanned_at': self.scanned_at.isoformat(), 'scanned_by': self.scanned_by,
        }
    class Meta: ordering = ['-scanned_at']
 
class AuditLog(models.Model):
    """Immutable audit trail. FR-14."""
    user_id        = models.CharField(max_length=100, db_index=True)
    event_type     = models.CharField(max_length=100)
    target         = models.CharField(max_length=255, blank=True)
    timestamp      = models.DateTimeField(auto_now_add=True, db_index=True)
    result_summary = models.CharField(max_length=500, blank=True)
    ip_address     = models.GenericIPAddressField(null=True, blank=True)
    user_agent     = models.CharField(max_length=300, blank=True)
    def to_dict(self):
        return {'id': self.id, 'user_id': self.user_id,
                'event_type': self.event_type, 'target': self.target,
                'timestamp': self.timestamp.isoformat(), 'result_summary': self.result_summary}
    class Meta: ordering = ['-timestamp']
 
class ScheduledScan(models.Model):
    """Scheduled scan jobs. FR-12."""
    name       = models.CharField(max_length=100)
    targets    = models.TextField()   # JSON list of hostnames
    frequency  = models.CharField(max_length=20, default='daily')
    cron_hour  = models.IntegerField(default=2)
    cron_minute= models.IntegerField(default=0)
    is_enabled = models.BooleanField(default=True)
    last_run   = models.DateTimeField(null=True, blank=True)

    created_by = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta: ordering = ['-created_at']



