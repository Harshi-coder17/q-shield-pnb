from functools import wraps
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
 
ROLE_PERMISSIONS = {
    'admin':   {'scan','view','export','configure','manage_users','view_logs'},
    'checker': {'view', 'export'},
    'auditor': {'view'},
}
 
def get_user_role(request) -> str:
    try:    return request.user.profile.role
    except: return 'auditor'
 
def has_permission(request, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(get_user_role(request), set())
 
def require_permission(permission: str):
    """Decorator — returns 403 JSON if user lacks permission."""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(request, *args, **kwargs):
            if not has_permission(request, permission):
                return JsonResponse({
                    'error': f'Permission denied. Required: {permission}.',
                    'your_role': get_user_role(request)
                }, status=403)
            return view_func(request, *args, **kwargs)
        return wrapped
    return decorator
