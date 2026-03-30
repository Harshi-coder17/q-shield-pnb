# backend/qshield/apps.py
from django.apps import AppConfig
 
class QshieldConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'qshield'
 
    def ready(self):
        import os
        # RUN_MAIN prevents double-start in Django's dev autoreloader
        if os.environ.get('RUN_MAIN') != 'true':
            from scheduler import start_scheduler
            start_scheduler()
