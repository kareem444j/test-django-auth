import secrets
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

class DoubleSubmitCSRFMiddleware(MiddlewareMixin):
    """
    Double-submit cookie CSRF: compare csrftoken cookie with X-CSRFToken header
    Apply for unsafe methods only. You can configure exempt URLs in settings.CSRF_EXEMPT_URLS
    """
    def process_request(self, request):
        # safe methods -> allow
        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return None

        # optional exempt urls (configure in settings)
        exempt_urls = getattr(settings, "CSRF_EXEMPT_URLS", [])
        path = request.path_info or request.path
        for prefix in exempt_urls:
            if path == prefix:
                return None

        cookie = request.COOKIES.get("csrftoken")
        header = request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")

        if not cookie or not header or not secrets.compare_digest(cookie, header):
            return JsonResponse({"detail": "CSRF verification failed."}, status=403)

        return None
