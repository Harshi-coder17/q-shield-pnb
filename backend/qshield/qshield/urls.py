# backend/qshield/urls.py
# Q-Shield — API-Only URL Configuration
# Owner: Member 2 (Django Backend & API Infrastructure Engineer)
 
from django.contrib import admin
from django.urls import path
from qshield import views
 
urlpatterns = [
    path('admin/', admin.site.urls),
    # ── Auth API (frontend calls these via fetch) ──
    path('api/csrf/',    views.api_csrf,    name='api_csrf'),
    path('api/login/',   views.api_login,   name='api_login'),
    path('api/logout/',  views.api_logout,  name='api_logout'),
    path('api/me/',      views.api_me,      name='api_me'),
    # ── Scan API ──
    path('api/scan/',        views.api_scan,       name='api_scan'),
    path('api/scan/batch/',  views.api_batch_scan, name='api_batch_scan'),
    path('api/discover/',    views.api_discover,   name='api_discover'),
    # ── Data API ──
    path('api/results/',    views.api_results,   name='api_results'),
    path('api/summary/',    views.api_summary,   name='api_summary'),
    path('api/assets/',     views.api_assets,    name='api_assets'),
    path('api/graph/',      views.api_graph,     name='api_graph'),
    path('api/audit-log/',  views.api_audit_log, name='api_audit_log'),
    # ── Export API ──
    path('api/export/json/', views.export_json, name='export_json'),
    path('api/export/csv/',  views.export_csv,  name='export_csv'),
    path('api/export/pdf/',  views.export_pdf,  name='export_pdf'),
    # ── Schedules API ──
    path('api/schedules/', views.api_schedules, name='api_schedules'),
]
