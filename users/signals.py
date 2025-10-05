from django.dispatch import receiver
from axes.signals import user_locked_out
from rest_framework.exceptions import PermissionDenied

@receiver(user_locked_out)
def raise_permission_denied_on_lockout(sender, request, username=None, ip_address=None, **kwargs):
    # لما axes يطلع ان المستخدم/الـ ip اتقفلو، نرمي استثناء DRF
    raise PermissionDenied("Too many failed login attempts")
