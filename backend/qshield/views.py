# backend/qshield/views.py
 
import json, sys, os
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from qshield.models import ScanResult, AuditLog, Asset, ScheduledScan
from qshield.auth.rbac import require_permission, get_user_role
from qshield.utils.logger import audit
 
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
 
# ── AUTH API ──────────────────────────────────────────────────────
@ensure_csrf_cookie
@require_http_methods(['GET'])
def api_csrf(request):
    """Frontend calls GET /api/csrf/ first to receive CSRF cookie."""
    return JsonResponse({'detail': 'CSRF cookie set'})
 
@require_http_methods(['POST'])
def api_login(request):
    try: data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    user = authenticate(request,
                        username=data.get('username', '').strip(),
                        password=data.get('password', ''))
    if user:
        login(request, user)
        role = get_user_role(request)
        audit(request, 'LOGIN', result_summary=f'Role: {role}')
        return JsonResponse({'success': True, 'username': user.username, 'role': role})
    audit(request, 'LOGIN_FAILED', target=data.get('username',''))
    return JsonResponse({'error': 'Invalid credentials'}, status=401)
 
@require_http_methods(['POST'])
@login_required
def api_logout(request):
    audit(request, 'LOGOUT')
    logout(request)
    return JsonResponse({'success': True})
 
@require_http_methods(['GET'])
@login_required
def api_me(request):
    return JsonResponse({'username': request.user.username,
                         'role': get_user_role(request), 'is_authenticated': True})
@require_http_methods(['POST'])
@require_permission('scan')
def api_scan(request):
    """FR-01 to FR-07: Single target scan."""
    try: data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    if 'url' not in data:
        return JsonResponse({'error': 'url field required'}, status=400)
 
    # CORRECT import path: utils.validators (NOT scanner.validators)
    from utils.validators import validate_target
    v = validate_target(data['url'])
    if not v['valid']:
        return JsonResponse({'error': v['error']}, status=400)
 
    hostname = v['hostname']
    from scanner.tls_scanner import TLSScanner
    tls_data = TLSScanner(hostname).scan()
    if tls_data.get('error'):
        audit(request, 'SCAN_FAILED', target=hostname, result_summary=tls_data['error'])
        return JsonResponse({'error': tls_data['error']}, status=500)
 
    cert_sha1   = tls_data.get('cert_sha1_fp', '')
    cert_reuse  = ScanResult.objects.filter(
        cert_sha1_fp=cert_sha1).exclude(hostname=hostname).exists()
 
    from analysis.scoring_engine import QuantumScoringEngine
    from analysis.hndl_analyzer  import HNDLAnalyzer
    from analysis.dep_graph      import DependencyGraphEngine
    from reporting.cbom_generator import CBOMGenerator
 
    score_result = QuantumScoringEngine().score(tls_data, cert_reuse)
    hndl  = HNDLAnalyzer().analyze(tls_data)
    cbom  = CBOMGenerator().generate_cbom([tls_data])
    graph = DependencyGraphEngine()
    for r in ScanResult.objects.all(): graph.add_scan_result(r.to_dict())
    graph.add_scan_result(tls_data)
 
    result = ScanResult.objects.create(
        hostname=hostname,
        tls_version=tls_data.get('tls_version',''), cipher_suite=tls_data.get('cipher_suite',''),
        cipher_bits=tls_data.get('cipher_bits'), key_exchange=tls_data.get('key_exchange',''),
        forward_secrecy=tls_data.get('forward_secrecy'), is_aead_cipher=tls_data.get('is_aead_cipher'),
        is_weak_cipher=tls_data.get('is_weak_cipher'), cert_subject=tls_data.get('cert_subject',''),
        cert_issuer=tls_data.get('cert_issuer',''), cert_not_before=tls_data.get('cert_not_before',''),
        cert_not_after=tls_data.get('cert_not_after',''),
        cert_days_remaining=tls_data.get('cert_days_remaining'),
        cert_sig_algorithm=tls_data.get('cert_sig_algorithm',''),
        cert_sig_oid=tls_data.get('cert_sig_oid',''), cert_key_size=tls_data.get('cert_key_size'),
        cert_sha1_fp=tls_data.get('cert_sha1_fp',''), cert_sha256_fp=tls_data.get('cert_sha256_fp',''),
        cert_san=json.dumps(tls_data.get('cert_san',[])), cert_verified=tls_data.get('cert_verified',True),
        quantum_score=score_result['score'], label=score_result['label']['text'],
        is_pqc_algorithm=score_result.get('is_pqc', False),
        dimension_scores=json.dumps(score_result['dimension_scores']),
        vulnerabilities=json.dumps(score_result['vulnerabilities']),
        recommendations=json.dumps(score_result['recommendations']),
        hndl_risk=hndl['hndl_risk'], hndl_explanation=hndl.get('explanation',''),
        cbom_json=json.dumps(cbom), scanned_by=request.user.username
    )
    Asset.objects.filter(hostname=hostname).update(last_scanned=timezone.now())
    audit(request, 'SCAN', target=hostname,
          result_summary=f"Score:{score_result['score']} Label:{score_result['label']['text']}")
 
    return JsonResponse({**tls_data,
        'score': score_result['score'], 'label': score_result['label'],
        'dimension_scores': score_result['dimension_scores'],
        'vulnerabilities':  score_result['vulnerabilities'],
        'recommendations':  score_result['recommendations'],
        'is_pqc': score_result.get('is_pqc', False),
        'hndl': hndl,'cbom': cbom, 'graph': graph.to_json()})
@require_http_methods(['POST'])
@require_permission('scan')
def api_batch_scan(request):
    data = json.loads(request.body)
    urls = data.get('urls', [])[:100]
    from utils.validators import validate_target
    from scanner.tls_scanner import TLSScanner
    from analysis.scoring_engine import QuantumScoringEngine
    scorer = QuantumScoringEngine()
    results = []
    for url in urls:
        v = validate_target(url)
        if not v['valid']:
            results.append({'url': url, 'error': v['error']}); continue
        tls = TLSScanner(v['hostname']).scan()
        if not tls.get('error'):
            cert_sha1  = tls.get('cert_sha1_fp', '')
            cert_reuse = ScanResult.objects.filter(
                cert_sha1_fp=cert_sha1).exclude(hostname=v['hostname']).exists()
            sr = scorer.score(tls, cert_reuse)
            results.append({**tls, 'score': sr['score'], 'label': sr['label']})
        else:
            results.append({'url': url, 'error': tls['error']})
    audit(request, 'BATCH_SCAN', result_summary=f'{len(urls)} targets')
    return JsonResponse({'count': len(results), 'results': results})
 
@require_http_methods(['GET'])
@require_permission('view')
def api_results(request):
    return JsonResponse([r.to_dict() for r in ScanResult.objects.all()], safe=False)
 
@require_http_methods(['GET'])
@require_permission('view')
def api_summary(request):
    results = list(ScanResult.objects.all())
    total   = len(results)
    label_counts = {}
    for r in results:
        label_counts[r.label] = label_counts.get(r.label, 0) + 1
    avg = sum(r.quantum_score or 0 for r in results)/total if total else 0
    es  = min(1000, int(avg * 10))
    tier = 'Elite-PQC' if es > 700 else 'Standard' if es >= 400 else 'Legacy'
    expiring = sum(1 for r in results if r.cert_days_remaining is not None and 0 <= r.cert_days_remaining < 30)
    expired  = sum(1 for r in results if r.cert_days_remaining is not None and r.cert_days_remaining < 0)
    return JsonResponse({'total': total, 'label_counts': label_counts,
                         'avg_score': round(avg,1), 'enterprise_score': es,
                         'enterprise_tier': tier, 'expiring_certs': expiring, 'expired_certs': expired})
 
@require_http_methods(['GET'])
@require_permission('export')
def export_json(request):
    from reporting.cbom_generator import CBOMGenerator
    cbom = CBOMGenerator().generate_cbom([r.to_dict() for r in ScanResult.objects.all()])
    audit(request, 'EXPORT', result_summary='JSON CBOM')
    return JsonResponse(cbom)
 
@require_http_methods(['GET'])
@require_permission('export')
def export_csv(request):
    from reporting.cbom_generator import CBOMGenerator
    g    = CBOMGenerator()
    cbom = g.generate_cbom([r.to_dict() for r in ScanResult.objects.all()])
    csv_str = g.to_csv(cbom)
    audit(request, 'EXPORT', result_summary='CSV CBOM')
    resp = HttpResponse(csv_str, content_type='text/csv')
    resp['Content-Disposition'] = 'attachment; filename=qshield_cbom.csv'
    return resp
 
@require_http_methods(['GET'])
@require_permission('export')
def export_pdf(request):
    from reporting.cbom_generator import CBOMGenerator
    from reporting.pdf_report     import PDFReportGenerator
    results   = [r.to_dict() for r in ScanResult.objects.all()]
    cbom      = CBOMGenerator().generate_cbom(results)
    pdf_bytes = PDFReportGenerator().generate(results, cbom)
    audit(request, 'EXPORT', result_summary='PDF Report')
    resp = HttpResponse(pdf_bytes, content_type='application/pdf')
    resp['Content-Disposition'] = 'attachment; filename=qshield_report.pdf'
    return resp

# ── TEMP STUBS (Phase 3+ integration pending) ──

@require_http_methods(['GET'])
@require_permission('view')
def api_discover(request):
    return JsonResponse({'status': 'discover endpoint ready'})

@require_http_methods(['GET'])
@require_permission('view')
def api_assets(request):
    assets = list(Asset.objects.all().values())
    return JsonResponse(assets, safe=False)

@require_http_methods(['GET'])
@require_permission('view')
def api_graph(request):
    from analysis.dep_graph import DependencyGraphEngine
    graph = DependencyGraphEngine()
    for r in ScanResult.objects.all():
        graph.add_scan_result(r.to_dict())
    return JsonResponse(graph.to_json())

@require_http_methods(['GET'])
@require_permission('view')
def api_audit_log(request):
    logs = list(AuditLog.objects.all().values())
    return JsonResponse(logs, safe=False)

@require_http_methods(['GET', 'POST'])
@require_permission('scan')
def api_schedules(request):
    if request.method == 'GET':
        schedules = list(ScheduledScan.objects.all().values())
        return JsonResponse(schedules, safe=False)
    return JsonResponse({'status': 'schedule creation pending'})