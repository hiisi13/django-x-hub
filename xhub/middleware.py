import hashlib
import hmac

from django.conf import settings
from django.http import HttpResponse


class XHubSignatureMiddleware(object):
    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        provided_signature = request.META.get('HTTP_X_HUB_SIGNATURE', None)
        if provided_signature:
            body = request.body.encode('utf-8')
            secret = settings.X_HUB_SECRET.encode('utf-8')

            signature = hmac.new(secret, body, hashlib.sha1)
            calculated_signature = 'sha1=' + signature.hexdigest()

            if calculated_signature != provided_signature:
                return HttpResponse(status=403)
    
        response = self.get_response(request)
        return response
