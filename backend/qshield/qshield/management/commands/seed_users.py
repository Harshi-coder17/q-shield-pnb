from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from qshield.models import UserProfile
 
class Command(BaseCommand):
    help = 'Seeds default Q-Shield users'
    def handle(self, *args, **options):
        users = [
            ('admin',   'PNBHackathon2026!', 'admin'),
            ('checker', 'Checker2026!',      'checker'),
        ]
        for username, password, role in users:
            if not User.objects.filter(username=username).exists():
                u = User.objects.create_user(username=username, password=password)
                UserProfile.objects.create(user=u, role=role)
                self.stdout.write(f'Created: {username} ({role})')
            else:
                self.stdout.write(f'Already exists: {username}')
