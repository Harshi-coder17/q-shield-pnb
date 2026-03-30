# backend/scheduler.py
 
import os, django, json, logging
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'qshield.settings')
# django.setup()  # MUST call before importing Django models
 
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron         import CronTrigger
from django.utils import timezone
from qshield.models import ScanResult, ScheduledScan, AuditLog
 
logger = logging.getLogger(__name__)
_scheduler = None
 
def run_scheduled_scan_job():
    from scanner.tls_scanner      import TLSScanner
    from analysis.scoring_engine  import QuantumScoringEngine
    from analysis.hndl_analyzer   import HNDLAnalyzer
    scorer = QuantumScoringEngine()
    hndl_a = HNDLAnalyzer()
    for job in ScheduledScan.objects.filter(is_enabled=True):
        for hostname in json.loads(job.targets or '[]'):
            try:
                tls_data = TLSScanner(hostname).scan()
                if tls_data.get('error'): continue
                score_result = scorer.score(tls_data)
                hndl         = hndl_a.analyze(tls_data)
                # FR-13 Change Detection
                prev = ScanResult.objects.filter(hostname=hostname).order_by('-scanned_at').first()
                if prev:
                    changed = []
                    if prev.tls_version  != tls_data.get('tls_version'):  changed.append('tls_version')
                    if prev.cipher_suite != tls_data.get('cipher_suite'): changed.append('cipher_suite')
                    if prev.cert_sha1_fp != tls_data.get('cert_sha1_fp'): changed.append('certificate')
                    if changed:
                        AuditLog.objects.create(
                            user_id='SCHEDULER', event_type='CONFIG_CHANGE_DETECTED',
                            target=hostname, result_summary=f'Changed: {", ".join(changed)}')
                        logger.warning(f'Config change on {hostname}: {changed}')
                ScanResult.objects.create(
                    hostname=hostname, tls_version=tls_data.get('tls_version',''),
                    cipher_suite=tls_data.get('cipher_suite',''),
                    cert_sig_algorithm=tls_data.get('cert_sig_algorithm',''),
                    cert_key_size=tls_data.get('cert_key_size'),
                    cert_sha1_fp=tls_data.get('cert_sha1_fp',''),
                    quantum_score=score_result['score'], label=score_result['label']['text'],
                    hndl_risk=hndl['hndl_risk'], scanned_by='SCHEDULER')
            except Exception as e:
                logger.error(f'Scheduled scan failed for {hostname}: {e}')
        job.last_run = timezone.now()
        job.save()
 
def start_scheduler():
    global _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(func=run_scheduled_scan_job,
                       trigger=CronTrigger(hour=2, minute=0),
                       id='daily_scan', replace_existing=True)
    _scheduler.start()
    logger.info('APScheduler started — daily scan at 02:00')
