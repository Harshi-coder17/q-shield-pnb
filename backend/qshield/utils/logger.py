# backend/qshield/utils/logger.py
# Q-Shield — Audit Trail  |  SRS FR-14
 
import logging
from qshield.models import AuditLog
 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.FileHandler('qshield_audit.log'), logging.StreamHandler()]
)
app_logger = logging.getLogger('qshield')
 
def audit(request, event_type: str, target: str = '',
          result_summary: str = '', user_id: str = None):
    uid = user_id or (
        request.user.username if request and request.user.is_authenticated
        else 'anonymous')
    ip = (request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
          or request.META.get('REMOTE_ADDR', '')) if request else ''
    ua = request.META.get('HTTP_USER_AGENT', '')[:300] if request else ''
    try:
        AuditLog.objects.create(
            user_id=uid, event_type=event_type,
            target=target, result_summary=result_summary,
            ip_address=ip or None, user_agent=ua)
    except Exception as e:
        app_logger.error(f'Audit DB write failed: {e}')
    app_logger.info(f'AUDIT | user={uid} | {event_type} | target={target} | {result_summary}')
